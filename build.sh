#!/bin/bash

docker run -ti -w /src -v .:/src -v /usr/src:/usr/src:ro -v /lib/modules/:/lib/modules:ro -v debugfs:/sys/kernel/debug:rw --net=host --pid=host --privileged dpf-dev:latest $@
