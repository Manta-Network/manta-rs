#!/usr/bin/env bash
shopt -s globstar
b3sum data/** 2>/dev/null > data.checkfile
