"use strict";(self.webpackChunkmy_website=self.webpackChunkmy_website||[]).push([[973],{3905:(e,t,r)=>{r.d(t,{Zo:()=>u,kt:()=>g});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var l=n.createContext({}),c=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},u=function(e){var t=c(e.components);return n.createElement(l.Provider,{value:t},e.children)},p="mdxType",m={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},d=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,o=e.originalType,l=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),p=c(r),d=a,g=p["".concat(l,".").concat(d)]||p[d]||m[d]||o;return r?n.createElement(g,i(i({ref:t},u),{},{components:r})):n.createElement(g,i({ref:t},u))}));function g(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=r.length,i=new Array(o);i[0]=d;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[p]="string"==typeof e?e:a,i[1]=s;for(var c=2;c<o;c++)i[c]=r[c];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}d.displayName="MDXCreateElement"},6147:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>i,default:()=>m,frontMatter:()=>o,metadata:()=>s,toc:()=>c});var n=r(7462),a=(r(7294),r(3905));const o={id:"usage",title:"Usage",sidebar_label:"Usage"},i=void 0,s={unversionedId:"reference/getting-started/usage",id:"reference/getting-started/usage",title:"Usage",description:"Polyglot Piranha can be used as a Python library or as a command-line tool.",source:"@site/docs/reference/getting-started/usage.md",sourceDirName:"reference/getting-started",slug:"/reference/getting-started/usage",permalink:"/piranha/docs/reference/getting-started/usage",draft:!1,editUrl:"https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/docs/reference/getting-started/usage.md",tags:[],version:"current",frontMatter:{id:"usage",title:"Usage",sidebar_label:"Usage"},sidebar:"docsSidebar",previous:{title:"Installation",permalink:"/piranha/docs/reference/getting-started/install"},next:{title:"Demos",permalink:"/piranha/docs/reference/getting-started/demos"}},l={},c=[{value:"Python API",id:"python-api",level:3},{value:"Command-line Interface",id:"command-line-interface",level:3}],u={toc:c},p="wrapper";function m(e){let{components:t,...r}=e;return(0,a.kt)(p,(0,n.Z)({},u,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("p",null,"Polyglot Piranha can be used as a Python library or as a command-line tool."),(0,a.kt)("h3",{id:"python-api"},"Python API"),(0,a.kt)("p",null,"Here's an example of how to use the Python API:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-python"},'from polyglot_piranha import execute_piranha, PiranhaArguments\n\npiranha_arguments = PiranhaArguments(\n    path_to_codebase = "...",\n    path_to_configurations = "...",\n    language= "java",\n    substitutions = {},\n    dry_run = False, \n    cleanup_comments = True\n)\npiranha_summary = execute_piranha(piranha_arguments)\n')),(0,a.kt)("h3",{id:"command-line-interface"},"Command-line Interface"),(0,a.kt)("p",null,"Here's an example of how to use the command-line interface:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"polyglot_piranha [OPTIONS] --path-to-codebase <PATH_TO_CODEBASE> --path-to-configurations <PATH_TO_CONFIGURATIONS> -l <LANGUAGE>\n")),(0,a.kt)("p",null,"For more detailed usage instructions, please refer to the ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/uber/piranha/blob/master/README.md"},"official documentation"),"."))}m.isMDXComponent=!0}}]);