#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 15:41:49 2026

@author: hounsousamuel
"""

def rebuild(pairs, fuzzer_cols, data):
    import pandas as pd
    to_return = []
    for path, df in list(pairs):
        to_append = [path, None]
        urls = list(df["url"].values)
        dfs = [data[url] for url in urls]
        final_df = pd.concat(dfs, axis=0)
        final_df.loc[:, fuzzer_cols] = df.loc[:, fuzzer_cols]
        final_df.loc[:, "url"] = df.loc[:, "url"]
        final_df.loc[:, "labels"] = df.loc[:, "labels"]
        final_df.reset_index(drop=True, inplace=True)
        to_append[1] = final_df
        to_return.append(to_append)
    
    return to_return