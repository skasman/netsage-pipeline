(window.webpackJsonp=window.webpackJsonp||[]).push([[31],{88:function(e,t,a){"use strict";a.r(t),a.d(t,"frontMatter",(function(){return l})),a.d(t,"metadata",(function(){return i})),a.d(t,"rightToc",(function(){return c})),a.d(t,"default",(function(){return p}));var n=a(2),o=a(6),r=(a(0),a(97)),l={id:"docker_advanced",title:"Docker Advanced Installation Guide",sidebar_label:"Docker Advanced"},i={unversionedId:"deploy/docker_advanced",id:"deploy/docker_advanced",isDocsHomePage:!1,title:"Docker Advanced Installation Guide",description:"Dockerized Nfdump",source:"@site/docs/deploy/docker_install_advanced.md",slug:"/deploy/docker_advanced",permalink:"/netsage-pipeline/docs/next/deploy/docker_advanced",editUrl:"https://github.com/netsage-project/netsage-pipeline/edit/master/website/docs/deploy/docker_install_advanced.md",version:"current",sidebar_label:"Docker Advanced",sidebar:"Docker",previous:{title:"Docker Default Installation Guide",permalink:"/netsage-pipeline/docs/next/deploy/docker_simple"},next:{title:"Troubleshooting",permalink:"/netsage-pipeline/docs/next/deploy/docker_troubleshoot"}},c=[{value:"Dockerized Nfdump",id:"dockerized-nfdump",children:[{value:"Step 1 Create a config",id:"step-1-create-a-config",children:[]},{value:"Step 2 Create an unique environment variable",id:"step-2-create-an-unique-environment-variable",children:[]},{value:"Step 3 Running the collectors",id:"step-3-running-the-collectors",children:[]}]},{value:"Running the Pipeline",id:"running-the-pipeline",children:[{value:"Environment file",id:"environment-file",children:[]},{value:"Custom Importer Config",id:"custom-importer-config",children:[]},{value:"Customize Logstash Settings",id:"customize-logstash-settings",children:[]},{value:"Kibana and Elastic Search",id:"kibana-and-elastic-search",children:[]},{value:"Bringing up the Pipeline",id:"bringing-up-the-pipeline",children:[]}]},{value:"Upgrading",id:"upgrading",children:[]}],s={rightToc:c};function p(e){var t=e.components,a=Object(o.a)(e,["components"]);return Object(r.b)("wrapper",Object(n.a)({},s,a,{components:t,mdxType:"MDXLayout"}),Object(r.b)("h2",{id:"dockerized-nfdump"},"Dockerized Nfdump"),Object(r.b)("p",null,"If you wish to use dockerized version of the collectors, then there are three components to be aware of."),Object(r.b)("ul",null,Object(r.b)("li",{parentName:"ul"},"collector docker container needs to run listening for sflow, or netflow traffic."),Object(r.b)("li",{parentName:"ul"},"an ENV value needs to be set that tags the sensor name."),Object(r.b)("li",{parentName:"ul"},"a unique data output path should be set."),Object(r.b)("li",{parentName:"ul"},"importer needs to be updated to be aware of the filepath and the sensor name.")),Object(r.b)("h3",{id:"step-1-create-a-config"},"Step 1 Create a config"),Object(r.b)("p",null,"If you need to create more collectors the pattern is always the same. Simply add"),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-yaml"}),'  uber-collector:\n    image: netsage/nfdump-collector:1.6.18\n    restart: always\n    command: sfcapd -T all -l /data -S 1 -w -z -p 9998\n    volumes:\n\n      - ./data/input_data/sflow:/data\n\n    ports:\n\n      - "9998:9998/udp\n\n')),Object(r.b)("ul",null,Object(r.b)("li",{parentName:"ul"},"collector-name: should be updated to something that has some meaning."),Object(r.b)("li",{parentName:"ul"},"command: there are several binaries available in the collector, including: ",Object(r.b)("inlineCode",{parentName:"li"},"nfanon, nfcapd,nfdump, nfexpire, nfreplay, sfcapd")," . You'll need to choose between sfcapd and nfcapd which are two processes that collect data. Define a port that will be used to capture data."),Object(r.b)("li",{parentName:"ul"},"ports: make sure this matches the port you've defined. Naturally all ports have to be unique for that host."),Object(r.b)("li",{parentName:"ul"},"Configure routers to point to the UDP port we've exposed on the given host."),Object(r.b)("li",{parentName:"ul"},"define a sensor name to use. The value doesn't matter but it has to be unique and we'll make the importer aware of it."),Object(r.b)("li",{parentName:"ul"},"volumes: make sure the path where the data is going in unique. In this case, we're persisting data to ./data/input_data/sflow. The last part of the path is usually changed to some unique identifier.")),Object(r.b)("p",null,"We're going to build an example custom configuration. The only changes we'll be making right now is\nto update the volums to this line."),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-yaml"}),"- ./data/input_data/uber_collector:/data\n")),Object(r.b)("h3",{id:"step-2-create-an-unique-environment-variable"},"Step 2 Create an unique environment variable"),Object(r.b)("p",null,"For this example I'm going to create a new env value in my .env file. I'm going to name my sensor uberSensor and then later make the importer aware of it."),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"uberSensor=magicValue\n")),Object(r.b)("p",null,"Also, if you are diverging from the default you will also need to create a custom importer configuration which will be stored at: /userConfig/netsage_override.xml. More will be explained under the importer custom section. Please uncomment the line in line under the importer in the override file."),Object(r.b)("h3",{id:"step-3-running-the-collectors"},"Step 3 Running the collectors"),Object(r.b)("p",null,"After selecting the docker version to run, you can start the collectors by running the following line:"),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose up -d uber-collector\n")),Object(r.b)("p",null,"Naturally the names of the services will need to be updated. Also if you haven't already done so you may remove any collectors you're not using from the override file (docker-compose.override.yml)."),Object(r.b)("div",{className:"admonition admonition-note alert alert--secondary"},Object(r.b)("div",Object(n.a)({parentName:"div"},{className:"admonition-heading"}),Object(r.b)("h5",{parentName:"div"},Object(r.b)("span",Object(n.a)({parentName:"h5"},{className:"admonition-icon"}),Object(r.b)("svg",Object(n.a)({parentName:"span"},{xmlns:"http://www.w3.org/2000/svg",width:"14",height:"16",viewBox:"0 0 14 16"}),Object(r.b)("path",Object(n.a)({parentName:"svg"},{fillRule:"evenodd",d:"M6.3 5.69a.942.942 0 0 1-.28-.7c0-.28.09-.52.28-.7.19-.18.42-.28.7-.28.28 0 .52.09.7.28.18.19.28.42.28.7 0 .28-.09.52-.28.7a1 1 0 0 1-.7.3c-.28 0-.52-.11-.7-.3zM8 7.99c-.02-.25-.11-.48-.31-.69-.2-.19-.42-.3-.69-.31H6c-.27.02-.48.13-.69.31-.2.2-.3.44-.31.69h1v3c.02.27.11.5.31.69.2.2.42.31.69.31h1c.27 0 .48-.11.69-.31.2-.19.3-.42.31-.69H8V7.98v.01zM7 2.3c-3.14 0-5.7 2.54-5.7 5.68 0 3.14 2.56 5.7 5.7 5.7s5.7-2.55 5.7-5.7c0-3.15-2.56-5.69-5.7-5.69v.01zM7 .98c3.86 0 7 3.14 7 7s-3.14 7-7 7-7-3.12-7-7 3.14-7 7-7z"})))),"note")),Object(r.b)("div",Object(n.a)({parentName:"div"},{className:"admonition-content"}),Object(r.b)("p",{parentName:"div"},"The default version of the collector is 1.6.18. There are other versions released and :latest should be point to the latest one, but there is no particular effort made to make sure we released the latest version. You can get a listing of all the current tags listed ",Object(r.b)("a",Object(n.a)({parentName:"p"},{href:"https://hub.docker.com/r/netsage/nfdump-collector/tags"}),"here")," and the source to generate the docker image can be found ",Object(r.b)("a",Object(n.a)({parentName:"p"},{href:"https://github.com/netsage-project/docker-nfdump-collector"}),"here")," the code for the You may use a different version though there is no particular effort to have an image for every nfdump release."))),Object(r.b)("h2",{id:"running-the-pipeline"},"Running the Pipeline"),Object(r.b)("p",null,"Once you've created the docker-compose.override.xml and finished adjusting it for any customizations, then you're ready to select your version."),Object(r.b)("p",null,"Before continuing you need to choose if you are going to be use the 'Develop' version which has the latest changes but might be a bit less stable or using the 'Release' version. If you're opting to use the Develop version, then simply skip the version selection step."),Object(r.b)("div",{className:"admonition admonition-caution alert alert--warning"},Object(r.b)("div",Object(n.a)({parentName:"div"},{className:"admonition-heading"}),Object(r.b)("h5",{parentName:"div"},Object(r.b)("span",Object(n.a)({parentName:"h5"},{className:"admonition-icon"}),Object(r.b)("svg",Object(n.a)({parentName:"span"},{xmlns:"http://www.w3.org/2000/svg",width:"16",height:"16",viewBox:"0 0 16 16"}),Object(r.b)("path",Object(n.a)({parentName:"svg"},{fillRule:"evenodd",d:"M8.893 1.5c-.183-.31-.52-.5-.887-.5s-.703.19-.886.5L.138 13.499a.98.98 0 0 0 0 1.001c.193.31.53.501.886.501h13.964c.367 0 .704-.19.877-.5a1.03 1.03 0 0 0 .01-1.002L8.893 1.5zm.133 11.497H6.987v-2.003h2.039v2.003zm0-3.004H6.987V5.987h2.039v4.006z"})))),"caution")),Object(r.b)("div",Object(n.a)({parentName:"div"},{className:"admonition-content"}),Object(r.b)("p",{parentName:"div"},"Warning! it is HIGHLY recommended to not use the :latest as that is intended to be a developer release. You may still use it but be aware that you may have some instability each time you update."))),Object(r.b)("ul",null,Object(r.b)("li",{parentName:"ul"},"Select Release version",Object(r.b)("ul",{parentName:"li"},Object(r.b)("li",{parentName:"ul"},Object(r.b)("inlineCode",{parentName:"li"},"git fetch; git checkout <tag name>"),' replace "tag name" with v1.2.5 or the version you intend to use.'),Object(r.b)("li",{parentName:"ul"},"Please select the version you wish to use using ",Object(r.b)("inlineCode",{parentName:"li"},"./scripts/docker_select_version.sh"))))),Object(r.b)("h3",{id:"environment-file"},"Environment file"),Object(r.b)("p",null,Object(r.b)("p",{parentName:"p"},"Please make a copy of the .env and refer back to the docker ",Object(r.b)("a",Object(n.a)({parentName:"p"},{href:"../devel/docker"}),"dev guide")," on details on configuring the env. Most of the default value should work just fine."),Object(r.b)("p",{parentName:"p"},"The only major change you should be aware of are the following values. The output host defines where the final data will land. The sensorName defines what the data will be labeled as."),Object(r.b)("p",{parentName:"p"},"If you don't send a sensor name it'll use the default docker hostname which changes each time you run the pipeline."),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-ini"}),"rabbitmq_output_host=rabbit\nrabbitmq_output_username=guest\nrabbitmq_output_pw=guest\nrabbitmq_output_key=netsage_archive_input\n\nsflowSensorName=sflowSensorName\nnetflowSensorName=netflowSensorName\n\n")),Object(r.b)("p",{parentName:"p"},"Please note, the default is to have one netflow collector and one sflow collector. If you need more collectors or do no need netflow or sflow simply comment out the collector you wish to ignore.")),Object(r.b)("h3",{id:"custom-importer-config"},"Custom Importer Config"),Object(r.b)("p",null,"The pipeline allows to have as many collectors as desired. You should have a unique sensorName ENV variable for each type and a unique path where data is being delivered."),Object(r.b)("p",null,"By convention everything is being written to ./data/input_data/sensorName You may change that behavior but just ensure the path between the colle"),Object(r.b)("ol",null,Object(r.b)("li",{parentName:"ol"},"Copy the compose/importer/netsage_shared.xml to userConfig/ and name it netsage_override.xml"),Object(r.b)("li",{parentName:"ol"},"In the docker-compose.yml uncomment the following line from the importer configuration.")),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"\n      - ./userConfig/netsage_override.xml:/etc/grnoc/netsage/deidentifier/netsage_shared.xml\n\n")),Object(r.b)("p",null,"This will use the ",Object(r.b)("inlineCode",{parentName:"p"},"netsage_override.xml")," in the userConfig instead of the container settings."),Object(r.b)("ol",{start:3},Object(r.b)("li",{parentName:"ol"},"Update collectors.")),Object(r.b)("p",null,"You may add as many new collectors as you like just ensure the following is unique:"),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-yml"}),'example-collector:\n  image: netsage/nfdump-collector:1.6.18\n  command: nfcapd -T all -l /data -S 1 -w -z -p 9999\n  ports:\n    - "9999:9999/udp"\n\n  restart: always\n  volumes:\n    - ./data/input_data/example:/data\n')),Object(r.b)("ul",null,Object(r.b)("li",{parentName:"ul"},"The command call should be updated. nfcapd for netflow, sfcapd for sflow"),Object(r.b)("li",{parentName:"ul"},"The output under volumes needs to be unique. Replace /example with the appropriate value"),Object(r.b)("li",{parentName:"ul"},"Make sure to update the port. The UDP port has to be unique. Please update the command and port mapping.")),Object(r.b)("p",null,"Technically you don't need to change to port of the command, but make sure you use the correct pattern when mapping the new settings."),Object(r.b)("p",null,"Example:"),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-yml"}),'ports:\n  - "9999:4321/udp"\n')),Object(r.b)("p",null,"The first port is the port on your host, the second port is the port on your local machine."),Object(r.b)("ol",{start:4},Object(r.b)("li",{parentName:"ol"},"Update the netsage_override.xml and add a new entry for the collector you're adding under the config section.")),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-xml"}),"    <collection>\n        <flow-path>/data/input_data/example</flow-path>\n        <sensor>$exampleSensorName</sensor>\n        <flow-type>sflow</flow-type>\n    </collection>\n\n")),Object(r.b)("ol",{start:5},Object(r.b)("li",{parentName:"ol"},"Update the environment file.")),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-ini"}),"exampleSensorName=example\n")),Object(r.b)("ol",{start:6},Object(r.b)("li",{parentName:"ol"},"At this point, please update the router configuration to send data to the new port you've defined. If the new collector is listening on 0.0.0.0:1234/udp then all traffic you wish grouped under")),Object(r.b)("p",null,"the new sensor should be send to 1234/udp."),Object(r.b)("p",null,"You will need to repeat steps 3-6 for each collector you're adding. For each new configuration the path, sensorName and exposed port have to be unique. Besides that, there is no limit\noutside of the bounds of the host's resources to how many collectors you may run."),Object(r.b)("h3",{id:"customize-logstash-settings"},"Customize Logstash Settings"),Object(r.b)("p",null,"Rename the provided example for JVM Options and tweak the settings as desired."),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"cp userConfig/jvm.options_example userConfig/jvm.options\n")),Object(r.b)("p",null,"Update the docker-compose.override.xml and ensure the logstash section is updated. It should look something along these lines."),Object(r.b)("pre",null,Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-yaml"}),"logstash:\n  image: netsage/pipeline_logstash:latest\n  volumes:\n    - ./userConfig/jvm.options:/usr/share/logstash/config/jvm.options\n")),Object(r.b)("h3",{id:"kibana-and-elastic-search"},"Kibana and Elastic Search"),Object(r.b)("p",null,"The file docker-compose.develop.yaml can be found in conjunction with docker-compose.yaml to bring up the optional Kibana and Elastic Search components."),Object(r.b)("p",null,"This isn't a production pattern but the tools can be useful at times. Please refer to the ",Object(r.b)("a",Object(n.a)({parentName:"p"},{href:"../devel/docker#optional-elasticsearch-and-kibana"}),"Docker Dev Guide")),Object(r.b)("h3",{id:"bringing-up-the-pipeline"},"Bringing up the Pipeline"),Object(r.b)("p",null,Object(r.b)("p",{parentName:"p"},"Starting up the pipeline using:"),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose up -d\n")),Object(r.b)("p",{parentName:"p"},"You can check the logs for each of the container by running"),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose logs\n")),Object(r.b)("h3",{parentName:"p"},"Shutting Down the pipeline."),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"docker-compose down\n"))),Object(r.b)("h2",{id:"upgrading"},"Upgrading"),Object(r.b)("p",null,Object(r.b)("h3",{parentName:"p"},"Update Source Code"),Object(r.b)("p",{parentName:"p"},"If your only changes are the version you selected simply reset and discard your changes."),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"git reset --hard\n")),Object(r.b)("p",{parentName:"p"},"Update the git repo. Likely this won't change anything but it's always a good practice to have the latest version. You will need to do at least a git fetch in order to see the latest tags."),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-sh"}),"git pull origin master\n")),Object(r.b)("h3",{parentName:"p"},"Collectors"),Object(r.b)("p",{parentName:"p"},"Since the collectors live outside of version control. Please check the docker-compose.override_example.yml and see if there any changes you need to bring in."),Object(r.b)("p",{parentName:"p"},"Likely the only change of note might be the docker version."),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{className:"language-yaml"}),'version: "3.7"\n')),Object(r.b)("h3",{parentName:"p"},"Select Release Version"),Object(r.b)("ol",{parentName:"p"},Object(r.b)("li",{parentName:"ol"},"git checkout <tag_value> (ie. v1.2.6, v1.2.7 etc)"),Object(r.b)("li",{parentName:"ol"},Object(r.b)("inlineCode",{parentName:"li"},"./scripts/docker_select_version.sh")," select the same version as the tag you checked out.")),Object(r.b)("h3",{parentName:"p"},"Update docker containers"),Object(r.b)("p",{parentName:"p"},"This applies for both development and release"),Object(r.b)("pre",{parentName:"p"},Object(r.b)("code",Object(n.a)({parentName:"pre"},{}),"docker-compose pull\n"))))}p.isMDXComponent=!0},97:function(e,t,a){"use strict";a.d(t,"a",(function(){return u})),a.d(t,"b",(function(){return m}));var n=a(0),o=a.n(n);function r(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function l(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function i(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?l(Object(a),!0).forEach((function(t){r(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):l(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function c(e,t){if(null==e)return{};var a,n,o=function(e,t){if(null==e)return{};var a,n,o={},r=Object.keys(e);for(n=0;n<r.length;n++)a=r[n],t.indexOf(a)>=0||(o[a]=e[a]);return o}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(n=0;n<r.length;n++)a=r[n],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(o[a]=e[a])}return o}var s=o.a.createContext({}),p=function(e){var t=o.a.useContext(s),a=t;return e&&(a="function"==typeof e?e(t):i(i({},t),e)),a},u=function(e){var t=p(e.components);return o.a.createElement(s.Provider,{value:t},e.children)},b={inlineCode:"code",wrapper:function(e){var t=e.children;return o.a.createElement(o.a.Fragment,{},t)}},d=o.a.forwardRef((function(e,t){var a=e.components,n=e.mdxType,r=e.originalType,l=e.parentName,s=c(e,["components","mdxType","originalType","parentName"]),u=p(a),d=n,m=u["".concat(l,".").concat(d)]||u[d]||b[d]||r;return a?o.a.createElement(m,i(i({ref:t},s),{},{components:a})):o.a.createElement(m,i({ref:t},s))}));function m(e,t){var a=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var r=a.length,l=new Array(r);l[0]=d;var i={};for(var c in t)hasOwnProperty.call(t,c)&&(i[c]=t[c]);i.originalType=e,i.mdxType="string"==typeof e?e:n,l[1]=i;for(var s=2;s<r;s++)l[s]=a[s];return o.a.createElement.apply(null,l)}return o.a.createElement.apply(null,a)}d.displayName="MDXCreateElement"}}]);