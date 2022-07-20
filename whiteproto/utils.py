"""Utils."""

from typing import Awaitable, Callable, TypeVar, ParamSpec
import atexit
import asyncio
import functools
import concurrent.futures

_T = TypeVar("_T")
_P = ParamSpec("_P")

_executor = concurrent.futures.ThreadPoolExecutor()


# Decorator for async run cpu bound functions
def cpu_bound_async(func: Callable[_P, _T]) -> Callable[_P, Awaitable[_T]]:
    """Run cpu-bound sync function as async.

    Uses ThreadPoolExecutor to run function in parallel.
    free_executor() must be called at shutdown to free
    process pool.

    Args:
        func: Function to run in parallel.

    Returns:
        Async function.
    """

    @functools.wraps(func)
    async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        _loop = asyncio.get_event_loop()
        return await _loop.run_in_executor(_executor, func, *args, **kwargs)

    return wrapper


def free_executor() -> None:
    """Free executor resources."""
    _executor.shutdown(wait=False, cancel_futures=True)
    atexit.unregister(free_executor)


atexit.register(free_executor)
