(window.webpackJsonp=window.webpackJsonp||[]).push([[23],{79:function(e,t,n){"use strict";n.r(t),n.d(t,"frontMatter",(function(){return l})),n.d(t,"metadata",(function(){return i})),n.d(t,"rightToc",(function(){return c})),n.d(t,"default",(function(){return u}));var a=n(2),o=n(6),r=(n(0),n(97)),l={id:"docker_install",title:"Docker Installation Guide",sidebar_label:"Docker Install"},i={unversionedId:"deploy/docker_install",id:"version-1.2.6/deploy/docker_install",isDocsHomePage:!1,title:"Docker Installation Guide",description:"The docker pattern is provided as much simpler and easier to use pattern that allows you to process and send data without having to deal with all",source:"@site/versioned_docs/version-1.2.6/deploy/docker_install.md",slug:"/deploy/docker_install",permalink:"/netsage-pipeline/docs/deploy/docker_install",editUrl:"https://github.com/netsage-project/netsage-pipeline/edit/master/website/versioned_docs/version-1.2.6/deploy/docker_install.md",version:"1.2.6",sidebar_label:"Docker Install",sidebar:"version-1.2.6/Pipeline",previous:{title:"NetSage Flow Processing Pipeline Install Guide",permalink:"/netsage-pipeline/docs/deploy/install"},next:{title:"Documentation Guide",permalink:"/netsage-pipeline/docs/docusaurus"}},c=[{value:"Nfdump",id:"nfdump",children:[{value:"External Nfdump",id:"external-nfdump",children:[]},{value:"Dockerized Nfdump",id:"dockerized-nfdump",children:[]}]},{value:"Common Pattern",id:"common-pattern",children:[{value:"Environment file",id:"environment-file",children:[]},{value:"Bringing up the Pipeline",id:"bringing-up-the-pipeline",children:[]},{value:"Shutting Down the pipeline.",id:"shutting-down-the-pipeline",children:[]},{value:"Advanced Configuration",id:"advanced-configuration",children:[]},{value:"Kibana and Elastic Search",id:"kibana-and-elastic-search",children:[]}]},{value:"Troubleshooting",id:"troubleshooting",children:[{value:"Data Flow issues:",id:"data-flow-issues",children:[]},{value:"Resource Limitations",id:"resource-limitations",children:[]}]},{value:"Upgrading",id:"upgrading",children:[{value:"Update Source Code",id:"update-source-code",children:[]},{value:"Update docker containers",id:"update-docker-containers",children:[]}]}],s={rightToc:c};function u(e){var t=e.components,n=Object(o.a)(e,["components"]);return Object(r.b)("wrapper",Object(a.a)({},s,n,{components:t,mdxType:"MDXLayout"}),Object(r.b)("p",null,"The docker pattern is provided as much simpler and easier to use pattern that allows you to process and send data without having to deal with all\nthe nuances of getting the pipeline setup."),Object(r.b)("p",null,"Before we start, you may have a read over the ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"../devel/docker"}),"developer docker guide")," it contains several notes such as how to select the docker version and likely other bits of information you may find useful."),Object(r.b)("h2",{id:"nfdump"},"Nfdump"),Object(r.b)("p",null,"Note that no matter if you use a localized version or take advantage of the docker container already built. You will need to configure your routers to send nfdump stats to the process collecting data on the host:port that you'll be defining."),Object(r.b)("p",null,"More info of nfdump can be found ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"https://github.com/phaag/nfdump/"}),"here")),Object(r.b)("h3",{id:"external-nfdump"},"External Nfdump"),Object(r.b)("p",null,"In this case you have nfdump running in your network somewhere and would like to keep on using it rather then relying on the container provided."),Object(r.b)("p",null,"You'll need to update your scripts to output to \\$PROJECT/data/input_data. Naturally all the paths are configurable but you'll have a much easier if you stick to the defaults."),Object(r.b)("p",null,"If you do choose to store the data elsewhere, the location may still need to be inside of the \\$PROJECT or a docker volume location in order for docker to be able to reference it."),Object(r.b)("p",null,"You will also need to configure your routers to point to the nfdump hostname and port in order for nfdump to collect data."),Object(r.b)("p",null,"At this point please proceed to ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"#common-pattern"}),"Common Pattern")),Object(r.b)("h3",{id:"dockerized-nfdump"},"Dockerized Nfdump"),Object(r.b)("p",null,"After you've selected the version of docker you'll be running. you can start the collector by simply running:"),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose up -d collector\n")),Object(r.b)("p",null,"The default version is 1.6.18. There are other versions released and :latest should be point to the latest one, but there is no particular effort made to make sure we released the latest version. You can get a listing of all the current tags listed ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"https://hub.docker.com/r/netsage/nfdump-collector/tags"}),"here")," and the source to generate the docker image can be found ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"https://github.com/netsage-project/docker-nfdump-collector"}),"here")," the code for the You may use a different version though there is no particular effort to have an image for every nfdump release."),Object(r.b)("p",null,"By default the container comes up and will write data to ",Object(r.b)("inlineCode",{parentName:"p"},"./data/input_data")," and listen to udp traffic on localhost:9999."),Object(r.b)("p",null,"continue to ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"#common-pattern"}),"Common Pattern")),Object(r.b)("h2",{id:"common-pattern"},"Common Pattern"),Object(r.b)("p",null,"Before continuing you need to choose if you are going to be use the 'Develop' version which has the latest changes but might be a bit less stable or using the 'Release' version."),Object(r.b)("ul",null,Object(r.b)("li",{parentName:"ul"},Object(r.b)("p",{parentName:"li"},"Development Version"),Object(r.b)("ul",{parentName:"li"},Object(r.b)("li",{parentName:"ul"},"Disregard anything about ",Object(r.b)("inlineCode",{parentName:"li"},"docker_select_version.sh")," that will not apply to you "),Object(r.b)("li",{parentName:"ul"},"Update to latest code git pull origin master"))),Object(r.b)("li",{parentName:"ul"},Object(r.b)("p",{parentName:"li"},"Release version"),Object(r.b)("ul",{parentName:"li"},Object(r.b)("li",{parentName:"ul"},Object(r.b)("inlineCode",{parentName:"li"},"git fetch; git checkout <tag name>"),' replace "tag name" with v1.2.5 or the version you intend to use.'),Object(r.b)("li",{parentName:"ul"},"Please select the version you wish to use using ",Object(r.b)("inlineCode",{parentName:"li"},"./scripts/docker_select_version.sh"),"\nit is HIGHLY recommended to not use the :latest as that is intended to be a developer release. You may still use it but be aware that you may have some instability each time you update.")))),Object(r.b)("h3",{id:"environment-file"},"Environment file"),Object(r.b)("p",null,"Please make a copy of the .env and refer back to the docker ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"../devel/docker"}),"dev guide")," on details on configuring the env. Most of the default value should work just fine."),Object(r.b)("p",null,"The only major change you should be aware of are the following values. The output host defines where the final data will land. The sensorName defines what the data will be labeled as."),Object(r.b)("p",null,"If you don't send a sensor name it'll use the default docker hostname which changes each time you run the pipeline."),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-ini"}),"rabbitmq_output_host=rabbit\nrabbitmq_output_username=guest\nrabbitmq_output_pw=guest\nrabbitmq_output_key=netsage_archive_input\n\nsflowSensorName=sflowSensorName\nnetflowSensorName=netflowSensorName\n\n")),Object(r.b)("p",null,"Please note, the default is to have one netflow collector and one sflow collector.  If you need more collectors or do no need netflow or sflow simply comment out the collector you wish to ignore."),Object(r.b)("h3",{id:"bringing-up-the-pipeline"},"Bringing up the Pipeline"),Object(r.b)("p",null,"Starting up the pipeline using:"),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose up -d\n")),Object(r.b)("p",null,"You can check the logs for each of the container by running"),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose logs\n")),Object(r.b)("h3",{id:"shutting-down-the-pipeline"},"Shutting Down the pipeline."),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose down\n")),Object(r.b)("h3",{id:"advanced-configuration"},"Advanced Configuration"),Object(r.b)("p",null,"The pipeline allows to have as many collectors as desired.  You should have a unique sensorName ENV variable for each type and a unique path where data is being delivered."),Object(r.b)("p",null,"By convention everything is being written to ./data/input_data/sensorName You may change that behavior but just ensure the path between the colle"),Object(r.b)("ol",null,Object(r.b)("li",{parentName:"ol"},"Copy the compose/importer/netsage_shared.xml to userConfig/ and name it netsage_override.xml"),Object(r.b)("li",{parentName:"ol"},"In the docker-compose.yml uncomment the following line from the importer configuration.")),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-sh"}),"\n      - ./userConfig/netsage_override.xml:/etc/grnoc/netsage/deidentifier/netsage_shared.xml\n\n")),Object(r.b)("p",null,"This will use the ",Object(r.b)("inlineCode",{parentName:"p"},"netsage_override.xml")," in the userConfig instead of the container settings."),Object(r.b)("ol",{start:3},Object(r.b)("li",{parentName:"ol"},"Update collectors.")),Object(r.b)("p",null,"You may add as many new collectors as you like just ensure the following is unique:"),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-yml"}),'  example-collector:\n    image: netsage/nfdump-collector:1.6.18\n    command: nfcapd -T all -l /data -S 1 -w -z -p 9999\n    ports:\n\n      - "9999:9999/udp"\n\n    restart: always\n    volumes:\n\n      - ./data/input_data/example:/data\n\n')),Object(r.b)("ul",null,Object(r.b)("li",{parentName:"ul"},Object(r.b)("p",{parentName:"li"},"The command call should be updated.  nfcapd for netflow, sfcapd for sflow")),Object(r.b)("li",{parentName:"ul"},Object(r.b)("p",{parentName:"li"},"The output under volumes needs to be unique. Replace /example with the appropriate value")),Object(r.b)("li",{parentName:"ul"},Object(r.b)("p",{parentName:"li"},"Make sure to update the port.  The UDP port has to be unique.  Please update the command and port mapping.  "),Object(r.b)("p",{parentName:"li"},"Technically you don't need to change to port of the command, but make sure you use the correct pattern when mapping the new settings."))),Object(r.b)("p",null,"Example: "),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-yml"}),'ports:\n\n      - "9999:4321/udp"\n\n')),Object(r.b)("p",null,"The first port is the port on your host, the second port is the port on your local machine. "),Object(r.b)("ol",{start:4},Object(r.b)("li",{parentName:"ol"},"Update the netsage_override.xml and add a new entry for the collector you're adding under the config section.")),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-xml"}),"    <collection>\n        <flow-path>/data/input_data/example</flow-path>\n        <sensor>$exampleSensorName</sensor> \n        <flow-type>sflow</flow-type>\n    </collection>\n\n")),Object(r.b)("ol",{start:5},Object(r.b)("li",{parentName:"ol"},"Update the environment file.")),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-ini"}),"exampleSensorName=example\n")),Object(r.b)("ol",{start:6},Object(r.b)("li",{parentName:"ol"},"At this point, please update the router configuration to send data to the new port you've defined.  If the new collector is listening on 0.0.0.0:1234/udp then all traffic you wish grouped under ")),Object(r.b)("p",null,"the new sensor should be send to 1234/udp.  "),Object(r.b)("p",null,"You will need to repeat steps 3-6 for each collector you're adding.  For each new configuration the path, sensorName and exposed port have to be unique.  Besides that, there is no limit\noutside of the bounds of the host's resources to how many collectors you may run."),Object(r.b)("h3",{id:"kibana-and-elastic-search"},"Kibana and Elastic Search"),Object(r.b)("p",null,"The file docker-compose.develop.yaml can be found in conjunction with docker-compose.yaml to bring up the optional Kibana and Elastic Search components."),Object(r.b)("p",null,"This isn't a production pattern but the tools can be useful at times. Please refer to the ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"../devel/docker#optional-elasticsearch-and-kibana"}),"Docker Dev Guide")),Object(r.b)("h2",{id:"troubleshooting"},"Troubleshooting"),Object(r.b)("h3",{id:"data-flow-issues"},"Data Flow issues:"),Object(r.b)("p",null,Object(r.b)("strong",{parentName:"p"},"Troubleshooting checklist:")),Object(r.b)("ul",null,Object(r.b)("li",{parentName:"ul"},"Make sure you configured your routers to point to the correct address/port where the collector is running.\xa0 hostname:9999 is the default."),Object(r.b)("li",{parentName:"ul"},"Make sure you created a .env file and updated the settings accordingly."),Object(r.b)("li",{parentName:"ul"},"sensorName especially since that identifies the source of the data.\xa0"),Object(r.b)("li",{parentName:"ul"},"check the logs of the various components to see if anything jumps out as being invalid.\xa0 docker-compose logs -f <service_label>")),Object(r.b)("h3",{id:"resource-limitations"},"Resource Limitations"),Object(r.b)("p",null,"If you are running a lot of data sometimes docker may need to be allocated more memory."),Object(r.b)("p",null,"Applying this snippet to logstash may help. Naturally the values will have to change."),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-yaml"}),"environment:\n\n  + LS_JAVA_OPTS=-Xmx3g\n\n")),Object(r.b)("p",null,"Alternatively you may also try doing this:"),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{className:"language-yaml"}),'deploy:\n  resources:\n    limits:\n      cpus: "0.50"\n      memory: 50M\n    reservations:\n      cpus: "0.25"\n      memory: 20M\n')),Object(r.b)("p",null,"Reference: ",Object(r.b)("a",Object(a.a)({parentName:"p"},{href:"https://docs.docker.com/compose/compose-file/#resources"}),"https://docs.docker.com/compose/compose-file/#resources")),Object(r.b)("h2",{id:"upgrading"},"Upgrading"),Object(r.b)("h3",{id:"update-source-code"},"Update Source Code"),Object(r.b)("p",null,"If your only changes are the version you selected simply reset and discard your changes."),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{}),"git reset --hard\n")),Object(r.b)("h4",{id:"development"},"Development"),Object(r.b)("p",null,"Update the git repo. Likely this won't change anything but it's always a good practice to have the latest version. You will need to do at least a git fetch in order to see the latest tags."),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{}),"git pull origin master\n")),Object(r.b)("h4",{id:"release"},"Release"),Object(r.b)("ol",null,Object(r.b)("li",{parentName:"ol"},"git checkout <tag_value> (ie. v1.2.6, v1.2.7 etc)"),Object(r.b)("li",{parentName:"ol"},Object(r.b)("inlineCode",{parentName:"li"},"./scripts/docker_select_version.sh")," select the same version as the tag you checked out.")),Object(r.b)("h3",{id:"update-docker-containers"},"Update docker containers"),Object(r.b)("p",null,"This applies for both development and release"),Object(r.b)("pre",null,Object(r.b)("code",Object(a.a)({parentName:"pre"},{}),"docker-compose pull\n")))}u.isMDXComponent=!0},97:function(e,t,n){"use strict";n.d(t,"a",(function(){return p})),n.d(t,"b",(function(){return h}));var a=n(0),o=n.n(a);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function l(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?l(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):l(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function c(e,t){if(null==e)return{};var n,a,o=function(e,t){if(null==e)return{};var n,a,o={},r=Object.keys(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var s=o.a.createContext({}),u=function(e){var t=o.a.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},p=function(e){var t=u(e.components);return o.a.createElement(s.Provider,{value:t},e.children)},d={inlineCode:"code",wrapper:function(e){var t=e.children;return o.a.createElement(o.a.Fragment,{},t)}},b=o.a.forwardRef((function(e,t){var n=e.components,a=e.mdxType,r=e.originalType,l=e.parentName,s=c(e,["components","mdxType","originalType","parentName"]),p=u(n),b=a,h=p["".concat(l,".").concat(b)]||p[b]||d[b]||r;return n?o.a.createElement(h,i(i({ref:t},s),{},{components:n})):o.a.createElement(h,i({ref:t},s))}));function h(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var r=n.length,l=new Array(r);l[0]=b;var i={};for(var c in t)hasOwnProperty.call(t,c)&&(i[c]=t[c]);i.originalType=e,i.mdxType="string"==typeof e?e:a,l[1]=i;for(var s=2;s<r;s++)l[s]=n[s];return o.a.createElement.apply(null,l)}return o.a.createElement.apply(null,n)}b.displayName="MDXCreateElement"}}]);