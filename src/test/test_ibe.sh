#!/bin/bash

mkdir wrk || true
cd wrk
../../build/app/setup
../../build/app/extract wrk
../../build/app/encrypt wrk
../../build/app/decrypt wrk