# SPEC-007 M2 — Interceptor chain and RPC classification

Spec milestone: SPEC-007 M2 (AC-16; GUARD-007-1; GUARD-007-5).

## Files and symbols

<!-- docref: begin src=sdk/nilcheck/nilcheck.go#Interface:e749e3a2,server/internal/auth/interceptors.go#ErrInterceptorChainNotWired:cd7ad180,server/internal/auth/interceptors.go#ProcedureClass:5ca29a75,server/internal/auth/interceptors.go#ProcedureClassifications:ceecbdd3,server/internal/auth/interceptors.go#ClassifyProcedure:0fcf3520,server/internal/auth/interceptors.go#InterceptorChain:4898645b,server/internal/auth/interceptors.go#NewInterceptorChain:12e02f2f,server/internal/auth/interceptors.go#InterceptorChain.ValidateWiring:7c2f7d76,server/internal/auth/interceptors.go#rejectedStreamingClientConn:cead73af,server/internal/control/handler.go#ErrServiceNotWired:85803ab0,server/internal/control/handler.go#NewHTTPHandler:b02ded58 -->
- `sdk/nilcheck/nilcheck.go`: `Interface`
- `server/internal/auth/interceptors.go`: `ErrInterceptorChainNotWired`,
  `ProcedureClass`, `ProcedureClassifications`, `ClassifyProcedure`,
  `InterceptorChain`, `NewInterceptorChain`, `rejectedStreamingClientConn`
- `server/internal/auth/interceptors_test.go`
- `server/internal/control/crl.go`, `server/internal/control/runtime.go`
- `server/internal/control/handler.go`: `ErrServiceNotWired`, `NewHTTPHandler`
- `server/internal/control/handler_test.go`
- `server/internal/control/auth_guard_test.go`
- `server/internal/pki/crl.go`, `server/internal/pki/enrollment.go`,
  `server/internal/pki/rotation.go`
- `docs/content/01-specs/00-index.md`
<!-- docref: end -->

## Test names

<!-- docref: begin src=sdk/nilcheck/nilcheck_test.go#TestInterface:edd47699,server/internal/auth/interceptors_test.go#TestGuard_RPCClassificationCoversEveryProcedure:c43e38a4,server/internal/auth/interceptors_test.go#TestProcedureClassifications_DefensivelyCopied:535d8c5b,server/internal/auth/interceptors_test.go#TestInterceptorChain_EnforcesOrder:0f22bfae,server/internal/auth/interceptors_test.go#TestNewInterceptorChain_RejectsMissingStages:f77d8d5d,server/internal/auth/interceptors_test.go#TestInterceptorChain_ShortCircuitsInOrder:cab9470e,server/internal/auth/interceptors_test.go#TestInterceptorChain_EnforcesStreamingHandlerOrder:445eba59,server/internal/auth/interceptors_test.go#TestInterceptorChain_ShortCircuitsStreamingHandlerInOrder:173dd14f,server/internal/auth/interceptors_test.go#TestInterceptorChain_InvalidStreamingClientFailsClosed:1d727ddf,server/internal/control/handler_test.go#TestNewHTTPHandler_RejectsMissingDependencies:46e95ce4,server/internal/control/auth_guard_test.go#TestGuard_ControlHandlersUseNoCookies:384264da,server/internal/control/auth_guard_test.go#TestGuard_ControlHandlersUseNoCookies_Liveness:436101a2 -->
- `TestInterface`
- `TestGuard_RPCClassificationCoversEveryProcedure`
- `TestProcedureClassifications_DefensivelyCopied`
- `TestInterceptorChain_EnforcesOrder`
- `TestNewInterceptorChain_RejectsMissingStages`
- `TestInterceptorChain_ShortCircuitsInOrder`
- `TestInterceptorChain_EnforcesStreamingHandlerOrder`
- `TestInterceptorChain_ShortCircuitsStreamingHandlerInOrder`
- `TestInterceptorChain_InvalidStreamingClientFailsClosed`
- `TestNewHTTPHandler_RejectsMissingDependencies`
- `TestGuard_ControlHandlersUseNoCookies`
- `TestGuard_ControlHandlersUseNoCookies_Liveness`
<!-- docref: end -->
