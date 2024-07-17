# torctrlgo - client to control your TOR instance
[![Go Reference](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fproxy.golang.org%2Fgithub.com%2F!code!spoof%2Ftorctrlgo%2F%40latest&query=%24.Version&logo=go&logoColor=white&label=Go)](https://pkg.go.dev/github.com/CodeSpoof/torctrlgo)
[![build](https://github.com/CodeSpoof/torctrlgo/actions/workflows/go.yml/badge.svg)](https://github.com/CodeSpoof/torctrlgo/actions/workflows/go.yml)

## Introduction

This is by far not a finished product.  
My testing capabilities are quite limited, since I don't have a running relay and some features aren't activated.  
Please report any bugs you encounter.

`torctrlgo` provides two different APIs.
- [high-level functions](#controller-high-level-api) built on top of inbuilt functions
- [low-level functions](#lowcontroller-low-level-api), directly defined by the TC1 ControlPort protocol

## Controller (high-level API)

The **Controller** API is under development.
This most likely won't change any time soon.
There are a wide variety of tasks, that could and should be implemented for ease of use.

If features aren't available using the **Controller** API, you can always access the **LowController** underneath.

I'm writing this mostly for fun. My use cases are limited and I have limited knowledge on which functions are needed and which functions are just too niche.  
I'd love to get suggestions and submissions for new functions for the **Controller** API.

## LowController (low-level API)

The **LowController** API is (for now) feature-complete.
It implements all functions provided by the protocol.
Future versions of TOR may change, how the protocol works and `torctrlgo` will need to be updated.
TOR defines how the protocol will change and `torctrlgo` implements many compatibility conditions.
In the foreseeable future, **LowController** shouldn't break easily.

For documentation see [here](https://pkg.go.dev/github.com/CodeSpoof/torctrlgo#LowController).  
To use this API I'd recommend looking at the [control-spec documentation](https://spec.torproject.org/control-spec/index.html) of TOR.
