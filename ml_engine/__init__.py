"""ML entry points imported on demand, without eagerly loading all stages."""

from importlib import import_module

_EXPORTS = {
    "predict": "predictor", "predict_batch": "predictor",
    "preprocess_data": "preprocess", "train_model": "train",
    "evaluate_model": "evaluate",
}
__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    value = getattr(import_module(f".{_EXPORTS[name]}", __name__), name)
    globals()[name] = value
    return value
