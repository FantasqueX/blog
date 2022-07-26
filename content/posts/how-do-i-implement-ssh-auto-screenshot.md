---
title: "How Do I Implement SSH Auto Screenshot"
date: 2022-07-26T11:58:15+08:00
summary: some experience in frontend development
categories: ["Random thoughts", "Frontend"]
---
This is a sequel to the previous post. There is one major flaw in the previous implementation. It cannot detect error occurring in SSH. A much simplified version is ` wt pwsh ssh xxx`. Windows terminal isn't able to run in the foreground like kconsole or gnome terminal. The command returns immediately and the main program isn't able to get the status of the following `pwsh ssh xxx`. What's more, inter process communication is also hard to implement. If they both use nodejs, maybe IPC is trivial. A simple but ugly work round is using file system to communicate. One side touches a file when an action has been done and the other side uses a while loop to check whether the specific file exists. This approach is ugly, however it works.

Can we make it better? I don't think there is something more elegant solution for the IPC. And there are some flaws in electron screenshot logic. I cannot know which window is the exact one I just opened using `child_process`. I have to enumerate all of them and check the name of window to make sure it is "pwsh.exe". If the program works in an intended way, the window is the first one. So I just the name of the first window. The problem here is what if there are two window with the same name or the user does something which disrupts the order? The conclusion is the program is not robust. There is another solution that using SSH to retrieve results and using some web technology to render an image which looks like a screenshot.

The naive idea is using `child_process` to get results of SSH, generating some HTML, and rendering it. I use XTermJS to generate HTML. The document of XTermJS is not so well and I have to guess how to use it. Fortunately, I just need a static and simple `sh` like HTML. `terminal.writeln()` is all I need. The next challenge is how to dynamically generate the HTML in runtime. If I would like to build a terminal, I'll use websockets. However it's complicate. I just need some `writeln` clauses in JavaScript. I come up with an idea to do something like template, escape results and string concatenate to generate a JavaScript file. As it's not elegant to directly use CSS files in node\_modules, I use webpack as bundling tool. Advantages of webpack are high quality document, easy to use nodejs API. Disadvantages are generated JavaScript files are ugly sticking to some standard prior to ES6. I also try to learn other bundling tools such as esbuild and vite. I don't know how to use esbuild after reading document on the official websites. It lacks tutorial how to build a VanillaJS project. Disadvantage of vite is I can only render thegenerated files through a HTTP server and it doesn't work if I just open the HTML file on the file system. BTW, I like files generated by vite. As of rendering, there is an awesome project puppeteer which allows you to use chrome API to screenshot web pages. I met two pits when using puppeteer. The first one is `tsc` complains that it cannot find the definition of `Element` used internally in puppeteer. The solution is add "dom" library to typescript libs. I think it should be included in document of puppeteer. Another thing is that screenshot results in my local chrome and chrome of puppeteer is not the same. That's weird! After some investigation, I find that results in headful chrome of puppeteer is correct. Maybe due to some weird JavaScript changing display in runtime. After deleting "xterm-addon-fit" plugin, it works well. I should pay more attention if chrome running in headless mode.

What if I want my program to work cross platform? There is no sshpass or nc(to use a socks proxy) in Windows. So I should look for some alternatives which is implemented in native JavaScript to use ssh and socks. I choose ssh2 and socks, which are under active maintenance. There is only one thing I would like to mention, to use ssh under socks proxy, just need to provide a socket. And the socks package provides a socket. They can work well.

Conclusion: The most significant problem is that I cannot use multiprocess in the current structure. If I can get rid of HTML in file system, then maybe it is able to use multiprocess.

Two small tips in frontend development:
1. Always use eslint and prettier. They are quite smart tools, and auto format can save you time.
2. Use npm scripts to make IDE happy with TypeScript. I was reluctant to use TypeScript previously because I have to click at least two times to run a TypeScript project. First using `tsc` to compile TypeScript code to JavaScript code. Then using `node` to run JavaScript code. However, I can define pre script and post script in npm scripts as follows.
```json
{
  "scripts": {
    "prestart": "tsc",
    "start": "node dist/main.js",
  }
}
```
Just one click to compile and run. Life is easier and happier :)
