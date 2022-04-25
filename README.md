# Transactional Locking II in C++
Transactional Locking II (TL2) is a software transactional memory (STM) algorithm based on a combination of commit-time locking and a global version-clock
based validation technique. This repository contains a C++ implementation of TL2 as described in the original TL2 [paper](https://dcl.epfl.ch/site/_media/education/4.pdf).

Note that the performance of this implementation somewhat suffers from STL overheads.

The code is meant to be run on an [evaluator](https://github.com/LPD-EPFL/CS453-2021-project), which compares its performance to a naive transactional memory implementation.
