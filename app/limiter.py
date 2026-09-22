"""Compatibility placeholder for the former FastAPI rate-limit integration."""


class _NoOpLimiter:
    def limit(self, *args, **kwargs):
        del args, kwargs
        def decorator(function):
            return function

        return decorator


limiter = _NoOpLimiter()