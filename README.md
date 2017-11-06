# Install steps:
1: Append the following parameters to configure:
   ./configure --add-module=mytest/ --add-module=myfilter/ --add-module=testslab/ \
   --with-cc-opt="-Wno-unused-function -Wno-write-strings"

2: Modify objs/Makefile to use g++ to build addons
   CXX = g++
   LINK = $(CXX)

3: For each addons, use CXX to replace CC:
   objs/addon/mytest/...:
       $(CXX) -c ...
   