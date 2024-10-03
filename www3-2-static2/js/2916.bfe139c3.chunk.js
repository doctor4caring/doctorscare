"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[2916],{95070:(e,a,s)=>{s.d(a,{Z:()=>k});var t=s(41418),r=s.n(t),l=s(72791),n=s(10162),o=s(80184);const c=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l="div",...c}=e;return t=(0,n.vE)(t,"card-body"),(0,o.jsx)(l,{ref:a,className:r()(s,t),...c})}));c.displayName="CardBody";const i=c,d=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l="div",...c}=e;return t=(0,n.vE)(t,"card-footer"),(0,o.jsx)(l,{ref:a,className:r()(s,t),...c})}));d.displayName="CardFooter";const m=d;var f=s(96040);const x=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,as:c="div",...i}=e;const d=(0,n.vE)(s,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,o.jsx)(f.Z.Provider,{value:m,children:(0,o.jsx)(c,{ref:a,...i,className:r()(t,d)})})}));x.displayName="CardHeader";const u=x,p=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,variant:l,as:c="img",...i}=e;const d=(0,n.vE)(s,"card-img");return(0,o.jsx)(c,{ref:a,className:r()(l?"".concat(d,"-").concat(l):d,t),...i})}));p.displayName="CardImg";const b=p,v=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l="div",...c}=e;return t=(0,n.vE)(t,"card-img-overlay"),(0,o.jsx)(l,{ref:a,className:r()(s,t),...c})}));v.displayName="CardImgOverlay";const N=v,y=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l="a",...c}=e;return t=(0,n.vE)(t,"card-link"),(0,o.jsx)(l,{ref:a,className:r()(s,t),...c})}));y.displayName="CardLink";const h=y;var j=s(27472);const w=(0,j.Z)("h6"),C=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l=w,...c}=e;return t=(0,n.vE)(t,"card-subtitle"),(0,o.jsx)(l,{ref:a,className:r()(s,t),...c})}));C.displayName="CardSubtitle";const E=C,I=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l="p",...c}=e;return t=(0,n.vE)(t,"card-text"),(0,o.jsx)(l,{ref:a,className:r()(s,t),...c})}));I.displayName="CardText";const Z=I,g=(0,j.Z)("h5"),R=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l=g,...c}=e;return t=(0,n.vE)(t,"card-title"),(0,o.jsx)(l,{ref:a,className:r()(s,t),...c})}));R.displayName="CardTitle";const F=R,P=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,bg:l,text:c,border:d,body:m=!1,children:f,as:x="div",...u}=e;const p=(0,n.vE)(s,"card");return(0,o.jsx)(x,{ref:a,...u,className:r()(t,p,l&&"bg-".concat(l),c&&"text-".concat(c),d&&"border-".concat(d)),children:m?(0,o.jsx)(i,{children:f}):f})}));P.displayName="Card";const k=Object.assign(P,{Img:b,Title:F,Subtitle:E,Body:i,Link:h,Text:Z,Header:u,Footer:m,ImgOverlay:N})},96040:(e,a,s)=>{s.d(a,{Z:()=>r});const t=s(72791).createContext(null);t.displayName="CardHeaderContext";const r=t},11701:(e,a,s)=>{s.d(a,{Ed:()=>l,UI:()=>r,XW:()=>n});var t=s(72791);function r(e,a){let s=0;return t.Children.map(e,(e=>t.isValidElement(e)?a(e,s++):e))}function l(e,a){let s=0;t.Children.forEach(e,(e=>{t.isValidElement(e)&&a(e,s++)}))}function n(e,a){return t.Children.toArray(e).some((e=>t.isValidElement(e)&&e.type===a))}},36638:(e,a,s)=>{s.d(a,{Z:()=>_});var t=s(41418),r=s.n(t),l=s(52007),n=s.n(l),o=s(72791),c=s(80184);const i={type:n().string,tooltip:n().bool,as:n().elementType},d=o.forwardRef(((e,a)=>{let{as:s="div",className:t,type:l="valid",tooltip:n=!1,...o}=e;return(0,c.jsx)(s,{...o,ref:a,className:r()(t,"".concat(l,"-").concat(n?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=i;const m=d;var f=s(84934),x=s(10162);const u=o.forwardRef(((e,a)=>{let{id:s,bsPrefix:t,className:l,type:n="checkbox",isValid:i=!1,isInvalid:d=!1,as:m="input",...u}=e;const{controlId:p}=(0,o.useContext)(f.Z);return t=(0,x.vE)(t,"form-check-input"),(0,c.jsx)(m,{...u,ref:a,type:n,id:s||p,className:r()(l,t,i&&"is-valid",d&&"is-invalid")})}));u.displayName="FormCheckInput";const p=u,b=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,htmlFor:l,...n}=e;const{controlId:i}=(0,o.useContext)(f.Z);return s=(0,x.vE)(s,"form-check-label"),(0,c.jsx)("label",{...n,ref:a,htmlFor:l||i,className:r()(t,s)})}));b.displayName="FormCheckLabel";const v=b;var N=s(11701);const y=o.forwardRef(((e,a)=>{let{id:s,bsPrefix:t,bsSwitchPrefix:l,inline:n=!1,reverse:i=!1,disabled:d=!1,isValid:u=!1,isInvalid:b=!1,feedbackTooltip:y=!1,feedback:h,feedbackType:j,className:w,style:C,title:E="",type:I="checkbox",label:Z,children:g,as:R="input",...F}=e;t=(0,x.vE)(t,"form-check"),l=(0,x.vE)(l,"form-switch");const{controlId:P}=(0,o.useContext)(f.Z),k=(0,o.useMemo)((()=>({controlId:s||P})),[P,s]),O=!g&&null!=Z&&!1!==Z||(0,N.XW)(g,v),T=(0,c.jsx)(p,{...F,type:"switch"===I?"checkbox":I,ref:a,isValid:u,isInvalid:b,disabled:d,as:R});return(0,c.jsx)(f.Z.Provider,{value:k,children:(0,c.jsx)("div",{style:C,className:r()(w,O&&t,n&&"".concat(t,"-inline"),i&&"".concat(t,"-reverse"),"switch"===I&&l),children:g||(0,c.jsxs)(c.Fragment,{children:[T,O&&(0,c.jsx)(v,{title:E,children:Z}),h&&(0,c.jsx)(m,{type:j,tooltip:y,children:h})]})})})}));y.displayName="FormCheck";const h=Object.assign(y,{Input:p,Label:v});s(42391);const j=o.forwardRef(((e,a)=>{let{bsPrefix:s,type:t,size:l,htmlSize:n,id:i,className:d,isValid:m=!1,isInvalid:u=!1,plaintext:p,readOnly:b,as:v="input",...N}=e;const{controlId:y}=(0,o.useContext)(f.Z);return s=(0,x.vE)(s,"form-control"),(0,c.jsx)(v,{...N,type:t,size:n,ref:a,readOnly:b,id:i||y,className:r()(d,p?"".concat(s,"-plaintext"):s,l&&"".concat(s,"-").concat(l),"color"===t&&"".concat(s,"-color"),m&&"is-valid",u&&"is-invalid")})}));j.displayName="FormControl";const w=Object.assign(j,{Feedback:m}),C=o.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:l="div",...n}=e;return t=(0,x.vE)(t,"form-floating"),(0,c.jsx)(l,{ref:a,className:r()(s,t),...n})}));C.displayName="FormFloating";const E=C,I=o.forwardRef(((e,a)=>{let{controlId:s,as:t="div",...r}=e;const l=(0,o.useMemo)((()=>({controlId:s})),[s]);return(0,c.jsx)(f.Z.Provider,{value:l,children:(0,c.jsx)(t,{...r,ref:a})})}));I.displayName="FormGroup";const Z=I;var g=s(53392);const R=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,id:l,...n}=e;const{controlId:i}=(0,o.useContext)(f.Z);return s=(0,x.vE)(s,"form-range"),(0,c.jsx)("input",{...n,type:"range",ref:a,className:r()(t,s),id:l||i})}));R.displayName="FormRange";const F=R,P=o.forwardRef(((e,a)=>{let{bsPrefix:s,size:t,htmlSize:l,className:n,isValid:i=!1,isInvalid:d=!1,id:m,...u}=e;const{controlId:p}=(0,o.useContext)(f.Z);return s=(0,x.vE)(s,"form-select"),(0,c.jsx)("select",{...u,size:l,ref:a,className:r()(n,s,t&&"".concat(s,"-").concat(t),i&&"is-valid",d&&"is-invalid"),id:m||p})}));P.displayName="FormSelect";const k=P,O=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,as:l="small",muted:n,...o}=e;return s=(0,x.vE)(s,"form-text"),(0,c.jsx)(l,{...o,ref:a,className:r()(t,s,n&&"text-muted")})}));O.displayName="FormText";const T=O,S=o.forwardRef(((e,a)=>(0,c.jsx)(h,{...e,ref:a,type:"switch"})));S.displayName="Switch";const L=Object.assign(S,{Input:h.Input,Label:h.Label}),V=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,children:l,controlId:n,label:o,...i}=e;return s=(0,x.vE)(s,"form-floating"),(0,c.jsxs)(Z,{ref:a,className:r()(t,s),controlId:n,...i,children:[l,(0,c.jsx)("label",{htmlFor:n,children:o})]})}));V.displayName="FloatingLabel";const z=V,K={_ref:n().any,validated:n().bool,as:n().elementType},H=o.forwardRef(((e,a)=>{let{className:s,validated:t,as:l="form",...n}=e;return(0,c.jsx)(l,{...n,ref:a,className:r()(s,t&&"was-validated")})}));H.displayName="Form",H.propTypes=K;const _=Object.assign(H,{Group:Z,Control:w,Floating:E,Check:h,Switch:L,Label:g.Z,Text:T,Range:F,Select:k,FloatingLabel:z})},84934:(e,a,s)=>{s.d(a,{Z:()=>t});const t=s(72791).createContext({})},53392:(e,a,s)=>{s.d(a,{Z:()=>m});var t=s(41418),r=s.n(t),l=s(72791),n=(s(42391),s(2677)),o=s(84934),c=s(10162),i=s(80184);const d=l.forwardRef(((e,a)=>{let{as:s="label",bsPrefix:t,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:x,...u}=e;const{controlId:p}=(0,l.useContext)(o.Z);t=(0,c.vE)(t,"form-label");let b="col-form-label";"string"===typeof d&&(b="".concat(b," ").concat(b,"-").concat(d));const v=r()(f,t,m&&"visually-hidden",d&&b);return x=x||p,d?(0,i.jsx)(n.Z,{ref:a,as:"label",className:v,htmlFor:x,...u}):(0,i.jsx)(s,{ref:a,className:v,htmlFor:x,...u})}));d.displayName="FormLabel";const m=d},19485:(e,a,s)=>{s.d(a,{Z:()=>b});s(72791);var t=s(80239),r=s(25561),l=s(36957),n=s(89102),o=s(94175),c=s(34886),i=s(84504),d=s(11701),m=s(3507),f=s(80184);function x(e){let a;return(0,d.Ed)(e,(e=>{null==a&&(a=e.props.eventKey)})),a}function u(e){const{title:a,eventKey:s,disabled:t,tabClassName:r,tabAttrs:l,id:c}=e.props;return null==a?null:(0,f.jsx)(o.Z,{as:"li",role:"presentation",children:(0,f.jsx)(n.Z,{as:"button",type:"button",eventKey:s,disabled:t,id:c,className:r,...l,children:a})})}const p=e=>{const{id:a,onSelect:s,transition:n,mountOnEnter:o=!1,unmountOnExit:p=!1,variant:b="tabs",children:v,activeKey:N=x(v),...y}=(0,t.Ch)(e,{activeKey:"onSelect"});return(0,f.jsxs)(r.Z,{id:a,activeKey:N,onSelect:s,transition:(0,m.Z)(n),mountOnEnter:o,unmountOnExit:p,children:[(0,f.jsx)(l.Z,{...y,role:"tablist",as:"ul",variant:b,children:(0,d.UI)(v,u)}),(0,f.jsx)(c.Z,{children:(0,d.UI)(v,(e=>{const a={...e.props};return delete a.title,delete a.disabled,delete a.tabClassName,delete a.tabAttrs,(0,f.jsx)(i.Z,{...a})}))})]})};p.displayName="Tabs";const b=p},97326:(e,a,s)=>{function t(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}s.d(a,{Z:()=>t})}}]);
//# sourceMappingURL=2916.bfe139c3.chunk.js.map