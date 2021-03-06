
SHELL=/bin/sh
MAKEFLAGS=-j8

CPLUS = g++
CC = gcc

INC =                           \
        -I.                     \
        -DNDEBUG                \

COPT =                          \
        -g0                     \
        -O6                     \
        -m64                    \
        -Wall                   \
        -msse3                  \
        -Wextra                 \
        -Wformat                \
        -pedantic               \
        -ffast-math             \
        -funroll-loops          \
        -Wno-deprecated         \
        -fstrict-aliasing       \
        -Wformat-security       \
        -Wstrict-aliasing=2     \
        -Wno-variadic-macros    \
        -fomit-frame-pointer    \
        -Wno-unused-variable    \
        -Wno-unused-parameter   \

CPLUSOPT = ${COPT}              \
        -std=c++0x              \
        -fno-check-new          \

LOPT =                          \
    -s                          \

LIBS =                          \
    -lcrypto                    \
    -ldl                        \

all:parser

.objs/callback.o : callback.cpp
	@echo c++ -- callback.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c callback.cpp -o .objs/callback.o
	@mv .objs/callback.d .deps

.objs/allBalances.o : cb/allBalances.cpp
	@echo c++ -- cb/allBalances.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c cb/allBalances.cpp -o .objs/allBalances.o
	@mv .objs/allBalances.d .deps

.objs/closure.o : cb/closure.cpp
	@echo c++ -- cb/closure.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c cb/closure.cpp -o .objs/closure.o
	@mv .objs/closure.d .deps

.objs/pristine.o : cb/pristine.cpp
	@echo c++ -- cb/pristine.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c cb/pristine.cpp -o .objs/pristine.o
	@mv .objs/pristine.d .deps

.objs/help.o : cb/help.cpp
	@echo c++ -- cb/help.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c cb/help.cpp -o .objs/help.o
	@mv .objs/help.d .deps

.objs/simpleStats.o : cb/simpleStats.cpp
	@echo c++ -- cb/simpleStats.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c cb/simpleStats.cpp -o .objs/simpleStats.o
	@mv .objs/simpleStats.d .deps

.objs/taint.o : cb/taint.cpp
	@echo c++ -- cb/taint.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c cb/taint.cpp -o .objs/taint.o
	@mv .objs/taint.d .deps

.objs/transactions.o : cb/transactions.cpp
	@echo c++ -- cb/transactions.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c cb/transactions.cpp -o .objs/transactions.o
	@mv .objs/transactions.d .deps

.objs/palindromes.o : cb/palindromes.cpp
	@echo c++ -- $<
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c $< -o $@
	@mv .objs/palindromes.d .deps

.objs/mathConstants.o : cb/mathConstants.cpp .objs/bignum.o
	@echo c++ -- $<
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c $< -o $@
	@mv .objs/mathConstants.d .deps

.objs/opcodes.o : opcodes.cpp
	@echo c++ -- opcodes.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c opcodes.cpp -o .objs/opcodes.o
	@mv .objs/opcodes.d .deps

.objs/parser.o : parser.cpp
	@echo c++ -- parser.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c parser.cpp -o .objs/parser.o
	@mv .objs/parser.d .deps

.objs/rmd160.o : rmd160.cpp
	@echo c++ -- rmd160.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c rmd160.cpp -o .objs/rmd160.o
	@mv .objs/rmd160.d .deps

.objs/sha256.o : sha256.cpp
	@echo c++ -- sha256.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c sha256.cpp -o .objs/sha256.o
	@mv .objs/sha256.d .deps

.objs/util.o : util.cpp
	@echo c++ -- util.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CPLUS} -MD ${INC} ${CPLUSOPT}  -c util.cpp -o .objs/util.o
	@mv .objs/util.d .deps

.objs/bignum.o : bignum.c
	@echo cc -- util.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	@${CC} -MD ${INC} ${COPT} -c $< -o $@
	@mv .objs/bignum.d .deps

OBJS=                       \
    .objs/callback.o        \
    .objs/allBalances.o     \
    .objs/closure.o         \
    .objs/help.o            \
    .objs/pristine.o        \
    .objs/simpleStats.o     \
    .objs/taint.o           \
    .objs/transactions.o    \
    .objs/palindromes.o     \
    .objs/mathConstants.o   \
    .objs/opcodes.o         \
    .objs/parser.o          \
    .objs/rmd160.o          \
    .objs/sha256.o          \
    .objs/util.o            \
    .objs/bignum.o          \

parser:${OBJS}
	@echo lnk -- parser 
	${CPLUS} ${LOPT} ${CPLUSOPT} -o parser ${OBJS} ${LIBS}

clean:
	-rm -r -f *.o *.i .objs .deps *.d parser

-include .deps/*

