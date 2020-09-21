(window.webpackJsonp=window.webpackJsonp||[]).push([[23],{77:function(e,t,r){"use strict";r.r(t),r.d(t,"frontMatter",(function(){return a})),r.d(t,"metadata",(function(){return i})),r.d(t,"rightToc",(function(){return l})),r.d(t,"default",(function(){return p}));var n=r(2),o=r(6),c=(r(0),r(89)),a={},i={unversionedId:"components/docker_upgrade",id:"components/docker_upgrade",isDocsHomePage:!1,title:"docker_upgrade",description:"Update Source Code",source:"@site/docs/components/docker_upgrade.md",slug:"/components/docker_upgrade",permalink:"/netsage-pipeline/docs/components/docker_upgrade",editUrl:"https://github.com/netsage-project/netsage-pipeline/edit/master/docs/components/docker_upgrade.md",version:"current"},l=[{value:"Update Source Code",id:"update-source-code",children:[]},{value:"Collectors",id:"collectors",children:[]},{value:"Select Release Version",id:"select-release-version",children:[]},{value:"Update docker containers",id:"update-docker-containers",children:[]}],s={rightToc:l};function p(e){var t=e.components,r=Object(o.a)(e,["components"]);return Object(c.b)("wrapper",Object(n.a)({},s,r,{components:t,mdxType:"MDXLayout"}),Object(c.b)("h3",{id:"update-source-code"},"Update Source Code"),Object(c.b)("p",null,"If your only changes are the version you selected simply reset and discard your changes."),Object(c.b)("pre",null,Object(c.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"git reset --hard\n")),Object(c.b)("p",null,"Update the git repo. Likely this won't change anything but it's always a good practice to have the latest version. You will need to do at least a git fetch in order to see the latest tags."),Object(c.b)("pre",null,Object(c.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"git pull origin master\n")),Object(c.b)("h3",{id:"collectors"},"Collectors"),Object(c.b)("p",null,"Since the collectors live outside of version control. Please check the docker-compose.override_example.yml and see if there any changes you need to bring in."),Object(c.b)("p",null,"Likely the only change of note might be the docker version."),Object(c.b)("pre",null,Object(c.b)("code",Object(n.a)({parentName:"pre"},{className:"language-yaml"}),'version: "3.7"\n')),Object(c.b)("h3",{id:"select-release-version"},"Select Release Version"),Object(c.b)("ol",null,Object(c.b)("li",{parentName:"ol"},"git checkout <tag_value> (ie. v1.2.6, v1.2.7 etc)"),Object(c.b)("li",{parentName:"ol"},Object(c.b)("inlineCode",{parentName:"li"},"./scripts/docker_select_version.sh")," select the same version as the tag you checked out.")),Object(c.b)("h3",{id:"update-docker-containers"},"Update docker containers"),Object(c.b)("p",null,"This applies for both development and release"),Object(c.b)("pre",null,Object(c.b)("code",Object(n.a)({parentName:"pre"},{}),"docker-compose pull\n")))}p.isMDXComponent=!0},89:function(e,t,r){"use strict";r.d(t,"a",(function(){return u})),r.d(t,"b",(function(){return m}));var n=r(0),o=r.n(n);function c(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){c(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},c=Object.keys(e);for(n=0;n<c.length;n++)r=c[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var c=Object.getOwnPropertySymbols(e);for(n=0;n<c.length;n++)r=c[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var s=o.a.createContext({}),p=function(e){var t=o.a.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},u=function(e){var t=p(e.components);return o.a.createElement(s.Provider,{value:t},e.children)},d={inlineCode:"code",wrapper:function(e){var t=e.children;return o.a.createElement(o.a.Fragment,{},t)}},b=o.a.forwardRef((function(e,t){var r=e.components,n=e.mdxType,c=e.originalType,a=e.parentName,s=l(e,["components","mdxType","originalType","parentName"]),u=p(r),b=n,m=u["".concat(a,".").concat(b)]||u[b]||d[b]||c;return r?o.a.createElement(m,i(i({ref:t},s),{},{components:r})):o.a.createElement(m,i({ref:t},s))}));function m(e,t){var r=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var c=r.length,a=new Array(c);a[0]=b;var i={};for(var l in t)hasOwnProperty.call(t,l)&&(i[l]=t[l]);i.originalType=e,i.mdxType="string"==typeof e?e:n,a[1]=i;for(var s=2;s<c;s++)a[s]=r[s];return o.a.createElement.apply(null,a)}return o.a.createElement.apply(null,r)}b.displayName="MDXCreateElement"}}]);