"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[151],{69764:(e,n,r)=>{r.d(n,{Z:()=>B});var a=r(81694),t=r.n(a),s=r(72791),o=r(80239),c=r(10162),i=r(75427),l=r(98328),d=r(71380);const f=function(){for(var e=arguments.length,n=new Array(e),r=0;r<e;r++)n[r]=arguments[r];return n.filter((e=>null!=e)).reduce(((e,n)=>{if("function"!==typeof n)throw new Error("Invalid Argument Type, must only provide functions, undefined, or null.");return null===e?n:function(){for(var r=arguments.length,a=new Array(r),t=0;t<r;t++)a[t]=arguments[t];e.apply(this,a),n.apply(this,a)}}),null)};var u=r(67202),m=r(14083),x=r(80184);const p={height:["marginTop","marginBottom"],width:["marginLeft","marginRight"]};function v(e,n){const r=n["offset".concat(e[0].toUpperCase()).concat(e.slice(1))],a=p[e];return r+parseInt((0,i.Z)(n,a[0]),10)+parseInt((0,i.Z)(n,a[1]),10)}const y={[l.Wj]:"collapse",[l.Ix]:"collapsing",[l.d0]:"collapsing",[l.cn]:"collapse show"},N=s.forwardRef(((e,n)=>{let{onEnter:r,onEntering:a,onEntered:o,onExit:c,onExiting:i,className:l,children:p,dimension:N="height",in:h=!1,timeout:E=300,mountOnEnter:b=!1,unmountOnExit:g=!1,appear:C=!1,getDimensionValue:j=v,...w}=e;const P="function"===typeof N?N():N,R=(0,s.useMemo)((()=>f((e=>{e.style[P]="0"}),r)),[P,r]),A=(0,s.useMemo)((()=>f((e=>{const n="scroll".concat(P[0].toUpperCase()).concat(P.slice(1));e.style[P]="".concat(e[n],"px")}),a)),[P,a]),O=(0,s.useMemo)((()=>f((e=>{e.style[P]=null}),o)),[P,o]),Z=(0,s.useMemo)((()=>f((e=>{e.style[P]="".concat(j(P,e),"px"),(0,u.Z)(e)}),c)),[c,j,P]),k=(0,s.useMemo)((()=>f((e=>{e.style[P]=null}),i)),[P,i]);return(0,x.jsx)(m.Z,{ref:n,addEndListener:d.Z,...w,"aria-expanded":w.role?h:null,onEnter:R,onEntering:A,onEntered:O,onExit:Z,onExiting:k,childRef:p.ref,in:h,timeout:E,mountOnEnter:b,unmountOnExit:g,appear:C,children:(e,n)=>s.cloneElement(p,{...n,className:t()(l,p.props.className,y[e],"width"===P&&"collapse-horizontal")})})}));function h(e,n){return Array.isArray(e)?e.includes(n):e===n}const E=s.createContext({});E.displayName="AccordionContext";const b=E,g=s.forwardRef(((e,n)=>{let{as:r="div",bsPrefix:a,className:o,children:i,eventKey:l,...d}=e;const{activeEventKey:f}=(0,s.useContext)(b);return a=(0,c.vE)(a,"accordion-collapse"),(0,x.jsx)(N,{ref:n,in:h(f,l),...d,className:t()(o,a),children:(0,x.jsx)(r,{children:s.Children.only(i)})})}));g.displayName="AccordionCollapse";const C=g,j=s.createContext({eventKey:""});j.displayName="AccordionItemContext";const w=j,P=s.forwardRef(((e,n)=>{let{as:r="div",bsPrefix:a,className:o,onEnter:i,onEntering:l,onEntered:d,onExit:f,onExiting:u,onExited:m,...p}=e;a=(0,c.vE)(a,"accordion-body");const{eventKey:v}=(0,s.useContext)(w);return(0,x.jsx)(C,{eventKey:v,onEnter:i,onEntering:l,onEntered:d,onExit:f,onExiting:u,onExited:m,children:(0,x.jsx)(r,{ref:n,...p,className:t()(o,a)})})}));P.displayName="AccordionBody";const R=P;const A=s.forwardRef(((e,n)=>{let{as:r="button",bsPrefix:a,className:o,onClick:i,...l}=e;a=(0,c.vE)(a,"accordion-button");const{eventKey:d}=(0,s.useContext)(w),f=function(e,n){const{activeEventKey:r,onSelect:a,alwaysOpen:t}=(0,s.useContext)(b);return s=>{let o=e===r?null:e;t&&(o=Array.isArray(r)?r.includes(e)?r.filter((n=>n!==e)):[...r,e]:[e]),null==a||a(o,s),null==n||n(s)}}(d,i),{activeEventKey:u}=(0,s.useContext)(b);return"button"===r&&(l.type="button"),(0,x.jsx)(r,{ref:n,onClick:f,...l,"aria-expanded":Array.isArray(u)?u.includes(d):d===u,className:t()(o,a,!h(u,d)&&"collapsed")})}));A.displayName="AccordionButton";const O=A,Z=s.forwardRef(((e,n)=>{let{as:r="h2",bsPrefix:a,className:s,children:o,onClick:i,...l}=e;return a=(0,c.vE)(a,"accordion-header"),(0,x.jsx)(r,{ref:n,...l,className:t()(s,a),children:(0,x.jsx)(O,{onClick:i,children:o})})}));Z.displayName="AccordionHeader";const k=Z,K=s.forwardRef(((e,n)=>{let{as:r="div",bsPrefix:a,className:o,eventKey:i,...l}=e;a=(0,c.vE)(a,"accordion-item");const d=(0,s.useMemo)((()=>({eventKey:i})),[i]);return(0,x.jsx)(w.Provider,{value:d,children:(0,x.jsx)(r,{ref:n,...l,className:t()(o,a)})})}));K.displayName="AccordionItem";const M=K,I=s.forwardRef(((e,n)=>{const{as:r="div",activeKey:a,bsPrefix:i,className:l,onSelect:d,flush:f,alwaysOpen:u,...m}=(0,o.Ch)(e,{activeKey:"onSelect"}),p=(0,c.vE)(i,"accordion"),v=(0,s.useMemo)((()=>({activeEventKey:a,onSelect:d,alwaysOpen:u})),[a,d,u]);return(0,x.jsx)(b.Provider,{value:v,children:(0,x.jsx)(r,{ref:n,...m,className:t()(l,p,f&&"".concat(p,"-flush"))})})}));I.displayName="Accordion";const B=Object.assign(I,{Button:O,Collapse:C,Item:M,Header:k,Body:R})},95070:(e,n,r)=>{r.d(n,{Z:()=>k});var a=r(81694),t=r.n(a),s=r(72791),o=r(10162),c=r(80184);const i=s.forwardRef(((e,n)=>{let{className:r,bsPrefix:a,as:s="div",...i}=e;return a=(0,o.vE)(a,"card-body"),(0,c.jsx)(s,{ref:n,className:t()(r,a),...i})}));i.displayName="CardBody";const l=i,d=s.forwardRef(((e,n)=>{let{className:r,bsPrefix:a,as:s="div",...i}=e;return a=(0,o.vE)(a,"card-footer"),(0,c.jsx)(s,{ref:n,className:t()(r,a),...i})}));d.displayName="CardFooter";const f=d;var u=r(96040);const m=s.forwardRef(((e,n)=>{let{bsPrefix:r,className:a,as:i="div",...l}=e;const d=(0,o.vE)(r,"card-header"),f=(0,s.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,c.jsx)(u.Z.Provider,{value:f,children:(0,c.jsx)(i,{ref:n,...l,className:t()(a,d)})})}));m.displayName="CardHeader";const x=m,p=s.forwardRef(((e,n)=>{let{bsPrefix:r,className:a,variant:s,as:i="img",...l}=e;const d=(0,o.vE)(r,"card-img");return(0,c.jsx)(i,{ref:n,className:t()(s?"".concat(d,"-").concat(s):d,a),...l})}));p.displayName="CardImg";const v=p,y=s.forwardRef(((e,n)=>{let{className:r,bsPrefix:a,as:s="div",...i}=e;return a=(0,o.vE)(a,"card-img-overlay"),(0,c.jsx)(s,{ref:n,className:t()(r,a),...i})}));y.displayName="CardImgOverlay";const N=y,h=s.forwardRef(((e,n)=>{let{className:r,bsPrefix:a,as:s="a",...i}=e;return a=(0,o.vE)(a,"card-link"),(0,c.jsx)(s,{ref:n,className:t()(r,a),...i})}));h.displayName="CardLink";const E=h;var b=r(27472);const g=(0,b.Z)("h6"),C=s.forwardRef(((e,n)=>{let{className:r,bsPrefix:a,as:s=g,...i}=e;return a=(0,o.vE)(a,"card-subtitle"),(0,c.jsx)(s,{ref:n,className:t()(r,a),...i})}));C.displayName="CardSubtitle";const j=C,w=s.forwardRef(((e,n)=>{let{className:r,bsPrefix:a,as:s="p",...i}=e;return a=(0,o.vE)(a,"card-text"),(0,c.jsx)(s,{ref:n,className:t()(r,a),...i})}));w.displayName="CardText";const P=w,R=(0,b.Z)("h5"),A=s.forwardRef(((e,n)=>{let{className:r,bsPrefix:a,as:s=R,...i}=e;return a=(0,o.vE)(a,"card-title"),(0,c.jsx)(s,{ref:n,className:t()(r,a),...i})}));A.displayName="CardTitle";const O=A,Z=s.forwardRef(((e,n)=>{let{bsPrefix:r,className:a,bg:s,text:i,border:d,body:f=!1,children:u,as:m="div",...x}=e;const p=(0,o.vE)(r,"card");return(0,c.jsx)(m,{ref:n,...x,className:t()(a,p,s&&"bg-".concat(s),i&&"text-".concat(i),d&&"border-".concat(d)),children:f?(0,c.jsx)(l,{children:u}):u})}));Z.displayName="Card";const k=Object.assign(Z,{Img:v,Title:O,Subtitle:j,Body:l,Link:E,Text:P,Header:x,Footer:f,ImgOverlay:N})},96040:(e,n,r)=>{r.d(n,{Z:()=>t});const a=r(72791).createContext(null);a.displayName="CardHeaderContext";const t=a},47022:(e,n,r)=>{r.d(n,{Z:()=>l});var a=r(81694),t=r.n(a),s=r(72791),o=r(10162),c=r(80184);const i=s.forwardRef(((e,n)=>{let{bsPrefix:r,fluid:a=!1,as:s="div",className:i,...l}=e;const d=(0,o.vE)(r,"container"),f="string"===typeof a?"-".concat(a):"-fluid";return(0,c.jsx)(s,{ref:n,...l,className:t()(i,a?"".concat(d).concat(f):d)})}));i.displayName="Container";const l=i},29546:(e,n,r)=>{r.d(n,{Z:()=>x});var a=r(72791),t=r(52007),s=r.n(t),o=r(1444),c=r(5107),i=r(20070);const l=s().oneOf(["start","end"]),d=s().oneOfType([l,s().shape({sm:l}),s().shape({md:l}),s().shape({lg:l}),s().shape({xl:l}),s().shape({xxl:l}),s().object]);var f=r(80184);const u={id:s().string,href:s().string,onClick:s().func,title:s().node.isRequired,disabled:s().bool,align:d,menuRole:s().string,renderMenuOnMount:s().bool,rootCloseEvent:s().string,menuVariant:s().oneOf(["dark"]),flip:s().bool,bsPrefix:s().string,variant:s().string,size:s().string},m=a.forwardRef(((e,n)=>{let{title:r,children:a,bsPrefix:t,rootCloseEvent:s,variant:l,size:d,menuRole:u,renderMenuOnMount:m,disabled:x,href:p,id:v,menuVariant:y,flip:N,...h}=e;return(0,f.jsxs)(o.Z,{ref:n,...h,children:[(0,f.jsx)(c.Z,{id:v,href:p,size:d,variant:l,disabled:x,childBsPrefix:t,children:r}),(0,f.jsx)(i.Z,{role:u,renderOnMount:m,rootCloseEvent:s,variant:y,flip:N,children:a})]})}));m.displayName="DropdownButton",m.propTypes=u;const x=m}}]);
//# sourceMappingURL=151.2bdc7975.chunk.js.map