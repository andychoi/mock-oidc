package routing

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

// Handler processes a normalized request.
type Handler func(*oauth2.Request) Response

// ResponseInterceptor may transform a response before it is written; applied
// to normal and error responses (interceptor failures on error responses are
// ignored, mirroring PathRouter).
type ResponseInterceptor func(*oauth2.Request, Response) Response

// Route matches by HTTP method (empty = any) and path suffix. A path
// containing "*" is treated as a regex over the full path (upstream
// routeFromPathAndMethod). The empty path matches every path.
type Route struct {
	Method string
	Path   string
	H      Handler

	pattern *regexp.Regexp
}

// Router is an ordered route table with response interceptors and the
// exception handler behavior of PathRouter.
type Router struct {
	routes       []Route
	interceptors []ResponseInterceptor
}

// New returns an empty router.
func New() *Router { return &Router{} }

// Add registers a route (later routes match after earlier ones).
func (rt *Router) Add(method, path string, h Handler) {
	r := Route{Method: method, Path: path, H: h}
	if strings.Contains(path, "*") {
		r.pattern = regexp.MustCompile("^(?:" + strings.ReplaceAll(path, "*", ".*") + ")$")
	}
	rt.routes = append(rt.routes, r)
}

// AddFront registers a route that matches before all previously registered
// routes (the additionalRoutes precedence of MockOAuth2Server).
func (rt *Router) AddFront(method, path string, h Handler) {
	r := Route{Method: method, Path: path, H: h}
	if strings.Contains(path, "*") {
		r.pattern = regexp.MustCompile("^(?:" + strings.ReplaceAll(path, "*", ".*") + ")$")
	}
	rt.routes = append([]Route{r}, rt.routes...)
}

// Get registers a GET route.
func (rt *Router) Get(path string, h Handler) { rt.Add(http.MethodGet, path, h) }

// Post registers a POST route.
func (rt *Router) Post(path string, h Handler) { rt.Add(http.MethodPost, path, h) }

// Any registers a method-agnostic route.
func (rt *Router) Any(path string, h Handler) { rt.Add("", path, h) }

// Options registers the catch-all OPTIONS route (empty path matches all).
func (rt *Router) Options(h Handler) { rt.Add(http.MethodOptions, "", h) }

// AddResponseInterceptor registers a response interceptor (e.g. CORS).
func (rt *Router) AddResponseInterceptor(i ResponseInterceptor) {
	rt.interceptors = append(rt.interceptors, i)
}

// ServeHTTP is the net/http entry point: normalize the request, dispatch to
// the first matching route, run interceptors, map panics/oauth2 errors to
// error responses.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := oauth2.FromHTTPRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	resp, errResp := rt.handle(req)
	if errResp != nil {
		resp = rt.applyInterceptors(req, ErrorResponse(errResp))
	}
	writeResponse(w, resp)
}

func (rt *Router) handle(req *oauth2.Request) (Response, *oauth2.Error) {
	route, found := rt.match(req)
	if !found {
		return MethodNotAllowed(), nil // see noMatch: the OPTIONS catch-all makes every path "known"
	}

	resp, oerr := invoke(route.H, req)
	if oerr != nil {
		return Response{}, toOAuth2Error(oerr)
	}
	return rt.applyInterceptors(req, resp), nil
}

// invoke runs a handler, converting panics into oauth2 errors.
func invoke(h Handler, req *oauth2.Request) (resp Response, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = panicToError(rec)
		}
	}()
	return h(req), nil
}

func (rt *Router) applyInterceptors(req *oauth2.Request, resp Response) Response {
	for _, i := range rt.interceptors {
		resp = i(req, resp)
	}
	return resp
}

func (rt *Router) match(req *oauth2.Request) (Route, bool) {
	for _, route := range rt.routes {
		if route.matches(req) {
			return route, true
		}
	}
	return Route{}, false
}

func (ro *Route) matches(req *oauth2.Request) bool {
	if ro.Method != "" && ro.Method != req.Method {
		return false
	}
	if ro.pattern != nil {
		return ro.pattern.MatchString("/" + strings.Trim(req.URL.Path, "/"))
	}
	trimmedPath := strings.Trim(req.URL.Path, "/")
	trimmedRoute := strings.Trim(ro.Path, "/")
	return strings.HasSuffix(trimmedPath, trimmedRoute)
}

func writeResponse(w http.ResponseWriter, resp Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.Status)
	if resp.BodyBytes != nil {
		_, _ = w.Write(resp.BodyBytes)
		return
	}
	_, _ = w.Write([]byte(resp.Body))
}

// panicToError maps a recovered panic to the exceptionHandler behavior:
// oauth2.Error as-is, anything else becomes server_error with a URL-encoded
// message.
func panicToError(rec any) *oauth2.Error {
	if oerr, ok := rec.(*oauth2.Error); ok {
		return oerr
	}
	if err, ok := rec.(error); ok {
		return oauth2.ServerError("unexpected exception with message: " + url.QueryEscape(err.Error()))
	}
	return oauth2.ServerError("unexpected exception")
}

func toOAuth2Error(err error) *oauth2.Error {
	if oerr, ok := err.(*oauth2.Error); ok {
		return oerr
	}
	return oauth2.ServerError("unexpected exception with message: " + url.QueryEscape(err.Error()))
}
