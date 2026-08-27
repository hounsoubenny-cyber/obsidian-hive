
_PARAMS = {
    "rf": {
        "n_estimators": lambda x: (f"{x}__n_estimators", 500, 5000),
        "max_depth": lambda x: (f"{x}__max_depth", [8, 12, 14, 16, None]),
        "max_features": lambda x: (f"{x}__max_features", ["sqrt", "log2", None]),
        "max_leaf_nodes": lambda x: (f"{x}__max_leaf_nodes", [31, 41, 51, None]),
    },
    "hgbc": {
        "n_estimators": lambda x: (f"{x}__n_estimators", 500, 5000),
        "max_depth": lambda x: (f"{x}__max_depth", [8, 12, 14, 16, None]),
        "max_features": lambda x: (f"{x}__max_features", ["sqrt", "log2", None]),
        "max_leaf_nodes": lambda x: (f"{x}__max_leaf_nodes", [31, 41, 51, None]),       
    }
}