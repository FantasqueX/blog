---
title: "How to Parser Input in Electron Application"
date: 2022-07-26T18:00:24+08:00
draft: true
---
Some days ago, I got a task to get positions of potential input such as request URL and read files in Electron applications.

At the beginning, I came up with a naive idea generating a list of input API, then following every invocations with these API. Just like a breadth-first search, eventually, I can get all positions of potential input.

The first part is get a list of input API. Let's focus on requesting URL API first. Nodejs uses `http.request` and `https.request` to request URL. Electron has an almost same API called `net.request`. And according to nodejs document, it is recommended to use third party http request package such as node-fetch and axios because nodejs API is too low level and not easy to use. We got a quite large list of the starting point.

The next part is implement a search algorithm. I met an ultra hard challenge here. Electron applications like vscode use OOP which means I cannot trace function calls using only function names. Instead, I must know the type of the object in case of two classes with method of the same name. If I statically analyse a JavaScript file, I cannot get the type of a variable. So I try to solve the problem using TypeScript compiler.

It's true that TypeScript compiler is able to get the type of a variable when parsing the AST according to the [wiki](https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API) of TypeScript. One weird thing is `ts.forEachChild` only enumerates all children without grandchildren. I have to recursively invoke my visit function.

Soon, I met another challenge. Function in JavaScript is just like number, object and something else. You can easily assign a function to a variable which means the API I interest may be assign to a property of an object through lots of if, loop, etc. Only type information is not enough. Let's take vscode as an example.

In `src/vs/platform/request`, vscode define the interface `IRequestService` which has a method `request`. There are several implementations in the same folder such as browser's XHR API, nodejs's http\(s\) request API and electron's net request API. In nodejs implementation, http request function is passed in as a parameter. A simple script cannot handle those complicate logics. Even identifying the initial position isn't a trivial thing.

```javascript
private async getNodeRequest(options: IRequestOptions): Promise<IRawRequestFunction> {
    const endpoint = parseUrl(options.url!);
    const module = endpoint.protocol === 'https:' ? await import('https') : await import('http');
    return module.request;
}
```

As above code shown, I cannot determine the type of `module` in compile time.

Lesson: Tainted analysis in OOP is difficult. Static analysis in JavaScript is hard.

