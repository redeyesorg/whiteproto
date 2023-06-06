"""Async executor."""

import asyncio
import atexit
import functools
from concurrent import futures
from typing import Awaitable, Callable, ParamSpec, TypeVar

T = TypeVar("T")  # noqa: WPS111
P = ParamSpec("P")  # noqa: WPS111

_executor = futures.ThreadPoolExecutor()


# Decorator for async run cpu bound functions
def cpu_bound_async(func: Callable[P, T]) -> Callable[P, Awaitable[T]]:
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
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, func, *args, **kwargs)

    return wrapper


def free_executor() -> None:
    """Free executor resources."""
    _executor.shutdown(wait=False, cancel_futures=True)
    atexit.unregister(free_executor)


atexit.register(free_executor)
