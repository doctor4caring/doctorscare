/*! For license information please see 6886.a9052bbc.chunk.js.LICENSE.txt */
(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6886],{67758:function(e,n,t){!function(e){"use strict";e.defineLocale("en-gb",{months:"January_February_March_April_May_June_July_August_September_October_November_December".split("_"),monthsShort:"Jan_Feb_Mar_Apr_May_Jun_Jul_Aug_Sep_Oct_Nov_Dec".split("_"),weekdays:"Sunday_Monday_Tuesday_Wednesday_Thursday_Friday_Saturday".split("_"),weekdaysShort:"Sun_Mon_Tue_Wed_Thu_Fri_Sat".split("_"),weekdaysMin:"Su_Mo_Tu_We_Th_Fr_Sa".split("_"),longDateFormat:{LT:"HH:mm",LTS:"HH:mm:ss",L:"DD/MM/YYYY",LL:"D MMMM YYYY",LLL:"D MMMM YYYY HH:mm",LLLL:"dddd, D MMMM YYYY HH:mm"},calendar:{sameDay:"[Today at] LT",nextDay:"[Tomorrow at] LT",nextWeek:"dddd [at] LT",lastDay:"[Yesterday at] LT",lastWeek:"[Last] dddd [at] LT",sameElse:"L"},relativeTime:{future:"in %s",past:"%s ago",s:"a few seconds",ss:"%d seconds",m:"a minute",mm:"%d minutes",h:"an hour",hh:"%d hours",d:"a day",dd:"%d days",M:"a month",MM:"%d months",y:"a year",yy:"%d years"},dayOfMonthOrdinalParse:/\d{1,2}(st|nd|rd|th)/,ordinal:function(e){var n=e%10;return e+(1===~~(e%100/10)?"th":1===n?"st":2===n?"nd":3===n?"rd":"th")},week:{dow:1,doy:4}})}(t(72426))},69764:(e,n,t)=>{"use strict";t.d(n,{Z:()=>D});var o=t(41418),r=t.n(o),a=t(72791),s=t(80239),i=t(10162),l=t(75427),c=t(98328),d=t(71380);const u=function(){for(var e=arguments.length,n=new Array(e),t=0;t<e;t++)n[t]=arguments[t];return n.filter((e=>null!=e)).reduce(((e,n)=>{if("function"!==typeof n)throw new Error("Invalid Argument Type, must only provide functions, undefined, or null.");return null===e?n:function(){for(var t=arguments.length,o=new Array(t),r=0;r<t;r++)o[r]=arguments[r];e.apply(this,o),n.apply(this,o)}}),null)};var m=t(67202),y=t(14083),f=t(80184);const p={height:["marginTop","marginBottom"],width:["marginLeft","marginRight"]};function h(e,n){const t=n["offset".concat(e[0].toUpperCase()).concat(e.slice(1))],o=p[e];return t+parseInt((0,l.Z)(n,o[0]),10)+parseInt((0,l.Z)(n,o[1]),10)}const x={[c.Wj]:"collapse",[c.Ix]:"collapsing",[c.d0]:"collapsing",[c.cn]:"collapse show"},v=a.forwardRef(((e,n)=>{let{onEnter:t,onEntering:o,onEntered:s,onExit:i,onExiting:l,className:c,children:p,dimension:v="height",in:_=!1,timeout:E=300,mountOnEnter:M=!1,unmountOnExit:g=!1,appear:b=!1,getDimensionValue:w=h,...N}=e;const C="function"===typeof v?v():v,L=(0,a.useMemo)((()=>u((e=>{e.style[C]="0"}),t)),[C,t]),A=(0,a.useMemo)((()=>u((e=>{const n="scroll".concat(C[0].toUpperCase()).concat(C.slice(1));e.style[C]="".concat(e[n],"px")}),o)),[C,o]),T=(0,a.useMemo)((()=>u((e=>{e.style[C]=null}),s)),[C,s]),j=(0,a.useMemo)((()=>u((e=>{e.style[C]="".concat(w(C,e),"px"),(0,m.Z)(e)}),i)),[i,w,C]),O=(0,a.useMemo)((()=>u((e=>{e.style[C]=null}),l)),[C,l]);return(0,f.jsx)(y.Z,{ref:n,addEndListener:d.Z,...N,"aria-expanded":N.role?_:null,onEnter:L,onEntering:A,onEntered:T,onExit:j,onExiting:O,childRef:p.ref,in:_,timeout:E,mountOnEnter:M,unmountOnExit:g,appear:b,children:(e,n)=>a.cloneElement(p,{...n,className:r()(c,p.props.className,x[e],"width"===C&&"collapse-horizontal")})})}));function _(e,n){return Array.isArray(e)?e.includes(n):e===n}const E=a.createContext({});E.displayName="AccordionContext";const M=E,g=a.forwardRef(((e,n)=>{let{as:t="div",bsPrefix:o,className:s,children:l,eventKey:c,...d}=e;const{activeEventKey:u}=(0,a.useContext)(M);return o=(0,i.vE)(o,"accordion-collapse"),(0,f.jsx)(v,{ref:n,in:_(u,c),...d,className:r()(s,o),children:(0,f.jsx)(t,{children:a.Children.only(l)})})}));g.displayName="AccordionCollapse";const b=g,w=a.createContext({eventKey:""});w.displayName="AccordionItemContext";const N=w,C=a.forwardRef(((e,n)=>{let{as:t="div",bsPrefix:o,className:s,onEnter:l,onEntering:c,onEntered:d,onExit:u,onExiting:m,onExited:y,...p}=e;o=(0,i.vE)(o,"accordion-body");const{eventKey:h}=(0,a.useContext)(N);return(0,f.jsx)(b,{eventKey:h,onEnter:l,onEntering:c,onEntered:d,onExit:u,onExiting:m,onExited:y,children:(0,f.jsx)(t,{ref:n,...p,className:r()(s,o)})})}));C.displayName="AccordionBody";const L=C;const A=a.forwardRef(((e,n)=>{let{as:t="button",bsPrefix:o,className:s,onClick:l,...c}=e;o=(0,i.vE)(o,"accordion-button");const{eventKey:d}=(0,a.useContext)(N),u=function(e,n){const{activeEventKey:t,onSelect:o,alwaysOpen:r}=(0,a.useContext)(M);return a=>{let s=e===t?null:e;r&&(s=Array.isArray(t)?t.includes(e)?t.filter((n=>n!==e)):[...t,e]:[e]),null==o||o(s,a),null==n||n(a)}}(d,l),{activeEventKey:m}=(0,a.useContext)(M);return"button"===t&&(c.type="button"),(0,f.jsx)(t,{ref:n,onClick:u,...c,"aria-expanded":Array.isArray(m)?m.includes(d):d===m,className:r()(s,o,!_(m,d)&&"collapsed")})}));A.displayName="AccordionButton";const T=A,j=a.forwardRef(((e,n)=>{let{as:t="h2",bsPrefix:o,className:a,children:s,onClick:l,...c}=e;return o=(0,i.vE)(o,"accordion-header"),(0,f.jsx)(t,{ref:n,...c,className:r()(a,o),children:(0,f.jsx)(T,{onClick:l,children:s})})}));j.displayName="AccordionHeader";const O=j,Y=a.forwardRef(((e,n)=>{let{as:t="div",bsPrefix:o,className:s,eventKey:l,...c}=e;o=(0,i.vE)(o,"accordion-item");const d=(0,a.useMemo)((()=>({eventKey:l})),[l]);return(0,f.jsx)(N.Provider,{value:d,children:(0,f.jsx)(t,{ref:n,...c,className:r()(s,o)})})}));Y.displayName="AccordionItem";const k=Y,S=a.forwardRef(((e,n)=>{const{as:t="div",activeKey:o,bsPrefix:l,className:c,onSelect:d,flush:u,alwaysOpen:m,...y}=(0,s.Ch)(e,{activeKey:"onSelect"}),p=(0,i.vE)(l,"accordion"),h=(0,a.useMemo)((()=>({activeEventKey:o,onSelect:d,alwaysOpen:m})),[o,d,m]);return(0,f.jsx)(M.Provider,{value:h,children:(0,f.jsx)(t,{ref:n,...y,className:r()(c,p,u&&"".concat(p,"-flush"))})})}));S.displayName="Accordion";const D=Object.assign(S,{Button:T,Collapse:b,Item:k,Header:O,Body:L})},29546:(e,n,t)=>{"use strict";t.d(n,{Z:()=>f});var o=t(72791),r=t(52007),a=t.n(r),s=t(1444),i=t(5107),l=t(20070);const c=a().oneOf(["start","end"]),d=a().oneOfType([c,a().shape({sm:c}),a().shape({md:c}),a().shape({lg:c}),a().shape({xl:c}),a().shape({xxl:c}),a().object]);var u=t(80184);const m={id:a().string,href:a().string,onClick:a().func,title:a().node.isRequired,disabled:a().bool,align:d,menuRole:a().string,renderMenuOnMount:a().bool,rootCloseEvent:a().string,menuVariant:a().oneOf(["dark"]),flip:a().bool,bsPrefix:a().string,variant:a().string,size:a().string},y=o.forwardRef(((e,n)=>{let{title:t,children:o,bsPrefix:r,rootCloseEvent:a,variant:c,size:d,menuRole:m,renderMenuOnMount:y,disabled:f,href:p,id:h,menuVariant:x,flip:v,..._}=e;return(0,u.jsxs)(s.Z,{ref:n,..._,children:[(0,u.jsx)(i.Z,{id:h,href:p,size:d,variant:c,disabled:f,childBsPrefix:r,children:t}),(0,u.jsx)(l.Z,{role:m,renderOnMount:y,rootCloseEvent:a,variant:x,flip:v,children:o})]})}));y.displayName="DropdownButton",y.propTypes=m;const f=y},95758:()=>{}}]);
//# sourceMappingURL=6886.a9052bbc.chunk.js.map