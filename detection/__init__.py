import warnings

# Deprecation notice raised inside torch_geometric on import. It does not come
# from this project and does not affect results. Only this one message is hidden.
warnings.filterwarnings(
    "ignore",
    message=r".*torch\.jit\.script.*is deprecated.*",
    category=FutureWarning,
)