#!/bin/sh
shopt -s globstar
b3sum data/** 2>/dev/null >data.checkfile
