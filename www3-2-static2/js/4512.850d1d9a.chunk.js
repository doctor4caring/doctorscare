"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[4512],{95070:(e,a,s)=>{s.d(a,{Z:()=>Z});var r=s(41418),t=s.n(r),l=s(72791),o=s(10162),c=s(80184);const n=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-body"),(0,c.jsx)(l,{ref:a,className:t()(s,r),...n})}));n.displayName="CardBody";const i=n,d=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-footer"),(0,c.jsx)(l,{ref:a,className:t()(s,r),...n})}));d.displayName="CardFooter";const f=d;var m=s(96040);const x=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,as:n="div",...i}=e;const d=(0,o.vE)(s,"card-header"),f=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,c.jsx)(m.Z.Provider,{value:f,children:(0,c.jsx)(n,{ref:a,...i,className:t()(r,d)})})}));x.displayName="CardHeader";const p=x,N=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,variant:l,as:n="img",...i}=e;const d=(0,o.vE)(s,"card-img");return(0,c.jsx)(n,{ref:a,className:t()(l?"".concat(d,"-").concat(l):d,r),...i})}));N.displayName="CardImg";const b=N,u=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-img-overlay"),(0,c.jsx)(l,{ref:a,className:t()(s,r),...n})}));u.displayName="CardImgOverlay";const v=u,y=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="a",...n}=e;return r=(0,o.vE)(r,"card-link"),(0,c.jsx)(l,{ref:a,className:t()(s,r),...n})}));y.displayName="CardLink";const h=y;var j=s(27472);const w=(0,j.Z)("h6"),C=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l=w,...n}=e;return r=(0,o.vE)(r,"card-subtitle"),(0,c.jsx)(l,{ref:a,className:t()(s,r),...n})}));C.displayName="CardSubtitle";const g=C,E=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="p",...n}=e;return r=(0,o.vE)(r,"card-text"),(0,c.jsx)(l,{ref:a,className:t()(s,r),...n})}));E.displayName="CardText";const R=E,F=(0,j.Z)("h5"),I=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l=F,...n}=e;return r=(0,o.vE)(r,"card-title"),(0,c.jsx)(l,{ref:a,className:t()(s,r),...n})}));I.displayName="CardTitle";const P=I,k=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,bg:l,text:n,border:d,body:f=!1,children:m,as:x="div",...p}=e;const N=(0,o.vE)(s,"card");return(0,c.jsx)(x,{ref:a,...p,className:t()(r,N,l&&"bg-".concat(l),n&&"text-".concat(n),d&&"border-".concat(d)),children:f?(0,c.jsx)(i,{children:m}):m})}));k.displayName="Card";const Z=Object.assign(k,{Img:b,Title:P,Subtitle:g,Body:i,Link:h,Text:R,Header:p,Footer:f,ImgOverlay:v})},96040:(e,a,s)=>{s.d(a,{Z:()=>t});const r=s(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,a,s)=>{s.d(a,{Ed:()=>l,UI:()=>t,XW:()=>o});var r=s(72791);function t(e,a){let s=0;return r.Children.map(e,(e=>r.isValidElement(e)?a(e,s++):e))}function l(e,a){let s=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&a(e,s++)}))}function o(e,a){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===a))}},36638:(e,a,s)=>{s.d(a,{Z:()=>B});var r=s(41418),t=s.n(r),l=s(52007),o=s.n(l),c=s(72791),n=s(80184);const i={type:o().string,tooltip:o().bool,as:o().elementType},d=c.forwardRef(((e,a)=>{let{as:s="div",className:r,type:l="valid",tooltip:o=!1,...c}=e;return(0,n.jsx)(s,{...c,ref:a,className:t()(r,"".concat(l,"-").concat(o?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=i;const f=d;var m=s(84934),x=s(10162);const p=c.forwardRef(((e,a)=>{let{id:s,bsPrefix:r,className:l,type:o="checkbox",isValid:i=!1,isInvalid:d=!1,as:f="input",...p}=e;const{controlId:N}=(0,c.useContext)(m.Z);return r=(0,x.vE)(r,"form-check-input"),(0,n.jsx)(f,{...p,ref:a,type:o,id:s||N,className:t()(l,r,i&&"is-valid",d&&"is-invalid")})}));p.displayName="FormCheckInput";const N=p,b=c.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,htmlFor:l,...o}=e;const{controlId:i}=(0,c.useContext)(m.Z);return s=(0,x.vE)(s,"form-check-label"),(0,n.jsx)("label",{...o,ref:a,htmlFor:l||i,className:t()(r,s)})}));b.displayName="FormCheckLabel";const u=b;var v=s(11701);const y=c.forwardRef(((e,a)=>{let{id:s,bsPrefix:r,bsSwitchPrefix:l,inline:o=!1,reverse:i=!1,disabled:d=!1,isValid:p=!1,isInvalid:b=!1,feedbackTooltip:y=!1,feedback:h,feedbackType:j,className:w,style:C,title:g="",type:E="checkbox",label:R,children:F,as:I="input",...P}=e;r=(0,x.vE)(r,"form-check"),l=(0,x.vE)(l,"form-switch");const{controlId:k}=(0,c.useContext)(m.Z),Z=(0,c.useMemo)((()=>({controlId:s||k})),[k,s]),T=!F&&null!=R&&!1!==R||(0,v.XW)(F,u),L=(0,n.jsx)(N,{...P,type:"switch"===E?"checkbox":E,ref:a,isValid:p,isInvalid:b,disabled:d,as:I});return(0,n.jsx)(m.Z.Provider,{value:Z,children:(0,n.jsx)("div",{style:C,className:t()(w,T&&r,o&&"".concat(r,"-inline"),i&&"".concat(r,"-reverse"),"switch"===E&&l),children:F||(0,n.jsxs)(n.Fragment,{children:[L,T&&(0,n.jsx)(u,{title:g,children:R}),h&&(0,n.jsx)(f,{type:j,tooltip:y,children:h})]})})})}));y.displayName="FormCheck";const h=Object.assign(y,{Input:N,Label:u});s(42391);const j=c.forwardRef(((e,a)=>{let{bsPrefix:s,type:r,size:l,htmlSize:o,id:i,className:d,isValid:f=!1,isInvalid:p=!1,plaintext:N,readOnly:b,as:u="input",...v}=e;const{controlId:y}=(0,c.useContext)(m.Z);return s=(0,x.vE)(s,"form-control"),(0,n.jsx)(u,{...v,type:r,size:o,ref:a,readOnly:b,id:i||y,className:t()(d,N?"".concat(s,"-plaintext"):s,l&&"".concat(s,"-").concat(l),"color"===r&&"".concat(s,"-color"),f&&"is-valid",p&&"is-invalid")})}));j.displayName="FormControl";const w=Object.assign(j,{Feedback:f}),C=c.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...o}=e;return r=(0,x.vE)(r,"form-floating"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...o})}));C.displayName="FormFloating";const g=C,E=c.forwardRef(((e,a)=>{let{controlId:s,as:r="div",...t}=e;const l=(0,c.useMemo)((()=>({controlId:s})),[s]);return(0,n.jsx)(m.Z.Provider,{value:l,children:(0,n.jsx)(r,{...t,ref:a})})}));E.displayName="FormGroup";const R=E;var F=s(53392);const I=c.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,id:l,...o}=e;const{controlId:i}=(0,c.useContext)(m.Z);return s=(0,x.vE)(s,"form-range"),(0,n.jsx)("input",{...o,type:"range",ref:a,className:t()(r,s),id:l||i})}));I.displayName="FormRange";const P=I,k=c.forwardRef(((e,a)=>{let{bsPrefix:s,size:r,htmlSize:l,className:o,isValid:i=!1,isInvalid:d=!1,id:f,...p}=e;const{controlId:N}=(0,c.useContext)(m.Z);return s=(0,x.vE)(s,"form-select"),(0,n.jsx)("select",{...p,size:l,ref:a,className:t()(o,s,r&&"".concat(s,"-").concat(r),i&&"is-valid",d&&"is-invalid"),id:f||N})}));k.displayName="FormSelect";const Z=k,T=c.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,as:l="small",muted:o,...c}=e;return s=(0,x.vE)(s,"form-text"),(0,n.jsx)(l,{...c,ref:a,className:t()(r,s,o&&"text-muted")})}));T.displayName="FormText";const L=T,O=c.forwardRef(((e,a)=>(0,n.jsx)(h,{...e,ref:a,type:"switch"})));O.displayName="Switch";const S=Object.assign(O,{Input:h.Input,Label:h.Label}),V=c.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,children:l,controlId:o,label:c,...i}=e;return s=(0,x.vE)(s,"form-floating"),(0,n.jsxs)(R,{ref:a,className:t()(r,s),controlId:o,...i,children:[l,(0,n.jsx)("label",{htmlFor:o,children:c})]})}));V.displayName="FloatingLabel";const z=V,H={_ref:o().any,validated:o().bool,as:o().elementType},_=c.forwardRef(((e,a)=>{let{className:s,validated:r,as:l="form",...o}=e;return(0,n.jsx)(l,{...o,ref:a,className:t()(s,r&&"was-validated")})}));_.displayName="Form",_.propTypes=H;const B=Object.assign(_,{Group:R,Control:w,Floating:g,Check:h,Switch:S,Label:F.Z,Text:L,Range:P,Select:Z,FloatingLabel:z})},84934:(e,a,s)=>{s.d(a,{Z:()=>r});const r=s(72791).createContext({})},53392:(e,a,s)=>{s.d(a,{Z:()=>f});var r=s(41418),t=s.n(r),l=s(72791),o=(s(42391),s(2677)),c=s(84934),n=s(10162),i=s(80184);const d=l.forwardRef(((e,a)=>{let{as:s="label",bsPrefix:r,column:d=!1,visuallyHidden:f=!1,className:m,htmlFor:x,...p}=e;const{controlId:N}=(0,l.useContext)(c.Z);r=(0,n.vE)(r,"form-label");let b="col-form-label";"string"===typeof d&&(b="".concat(b," ").concat(b,"-").concat(d));const u=t()(m,r,f&&"visually-hidden",d&&b);return x=x||N,d?(0,i.jsx)(o.Z,{ref:a,as:"label",className:u,htmlFor:x,...p}):(0,i.jsx)(s,{ref:a,className:u,htmlFor:x,...p})}));d.displayName="FormLabel";const f=d},97326:(e,a,s)=>{function r(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}s.d(a,{Z:()=>r})}}]);
//# sourceMappingURL=4512.850d1d9a.chunk.js.map