"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6690,0],{95070:(e,a,s)=>{s.d(a,{Z:()=>Z});var r=s(81694),t=s.n(r),l=s(72791),c=s(10162),o=s(80184);const n=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...n}=e;return r=(0,c.vE)(r,"card-body"),(0,o.jsx)(l,{ref:a,className:t()(s,r),...n})}));n.displayName="CardBody";const i=n,d=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...n}=e;return r=(0,c.vE)(r,"card-footer"),(0,o.jsx)(l,{ref:a,className:t()(s,r),...n})}));d.displayName="CardFooter";const f=d;var m=s(96040);const x=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,as:n="div",...i}=e;const d=(0,c.vE)(s,"card-header"),f=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,o.jsx)(m.Z.Provider,{value:f,children:(0,o.jsx)(n,{ref:a,...i,className:t()(r,d)})})}));x.displayName="CardHeader";const v=x,p=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,variant:l,as:n="img",...i}=e;const d=(0,c.vE)(s,"card-img");return(0,o.jsx)(n,{ref:a,className:t()(l?"".concat(d,"-").concat(l):d,r),...i})}));p.displayName="CardImg";const N=p,u=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...n}=e;return r=(0,c.vE)(r,"card-img-overlay"),(0,o.jsx)(l,{ref:a,className:t()(s,r),...n})}));u.displayName="CardImgOverlay";const b=u,h=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="a",...n}=e;return r=(0,c.vE)(r,"card-link"),(0,o.jsx)(l,{ref:a,className:t()(s,r),...n})}));h.displayName="CardLink";const y=h;var j=s(27472);const w=(0,j.Z)("h6"),g=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l=w,...n}=e;return r=(0,c.vE)(r,"card-subtitle"),(0,o.jsx)(l,{ref:a,className:t()(s,r),...n})}));g.displayName="CardSubtitle";const C=g,E=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="p",...n}=e;return r=(0,c.vE)(r,"card-text"),(0,o.jsx)(l,{ref:a,className:t()(s,r),...n})}));E.displayName="CardText";const I=E,R=(0,j.Z)("h5"),F=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l=R,...n}=e;return r=(0,c.vE)(r,"card-title"),(0,o.jsx)(l,{ref:a,className:t()(s,r),...n})}));F.displayName="CardTitle";const P=F,k=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,bg:l,text:n,border:d,body:f=!1,children:m,as:x="div",...v}=e;const p=(0,c.vE)(s,"card");return(0,o.jsx)(x,{ref:a,...v,className:t()(r,p,l&&"bg-".concat(l),n&&"text-".concat(n),d&&"border-".concat(d)),children:f?(0,o.jsx)(i,{children:m}):m})}));k.displayName="Card";const Z=Object.assign(k,{Img:N,Title:P,Subtitle:C,Body:i,Link:y,Text:I,Header:v,Footer:f,ImgOverlay:b})},96040:(e,a,s)=>{s.d(a,{Z:()=>t});const r=s(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,a,s)=>{s.d(a,{Ed:()=>l,UI:()=>t,XW:()=>c});var r=s(72791);function t(e,a){let s=0;return r.Children.map(e,(e=>r.isValidElement(e)?a(e,s++):e))}function l(e,a){let s=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&a(e,s++)}))}function c(e,a){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===a))}},36638:(e,a,s)=>{s.d(a,{Z:()=>_});var r=s(81694),t=s.n(r),l=s(52007),c=s.n(l),o=s(72791),n=s(80184);const i={type:c().string,tooltip:c().bool,as:c().elementType},d=o.forwardRef(((e,a)=>{let{as:s="div",className:r,type:l="valid",tooltip:c=!1,...o}=e;return(0,n.jsx)(s,{...o,ref:a,className:t()(r,"".concat(l,"-").concat(c?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=i;const f=d;var m=s(84934),x=s(10162);const v=o.forwardRef(((e,a)=>{let{id:s,bsPrefix:r,className:l,type:c="checkbox",isValid:i=!1,isInvalid:d=!1,as:f="input",...v}=e;const{controlId:p}=(0,o.useContext)(m.Z);return r=(0,x.vE)(r,"form-check-input"),(0,n.jsx)(f,{...v,ref:a,type:c,id:s||p,className:t()(l,r,i&&"is-valid",d&&"is-invalid")})}));v.displayName="FormCheckInput";const p=v,N=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,htmlFor:l,...c}=e;const{controlId:i}=(0,o.useContext)(m.Z);return s=(0,x.vE)(s,"form-check-label"),(0,n.jsx)("label",{...c,ref:a,htmlFor:l||i,className:t()(r,s)})}));N.displayName="FormCheckLabel";const u=N;var b=s(11701);const h=o.forwardRef(((e,a)=>{let{id:s,bsPrefix:r,bsSwitchPrefix:l,inline:c=!1,reverse:i=!1,disabled:d=!1,isValid:v=!1,isInvalid:N=!1,feedbackTooltip:h=!1,feedback:y,feedbackType:j,className:w,style:g,title:C="",type:E="checkbox",label:I,children:R,as:F="input",...P}=e;r=(0,x.vE)(r,"form-check"),l=(0,x.vE)(l,"form-switch");const{controlId:k}=(0,o.useContext)(m.Z),Z=(0,o.useMemo)((()=>({controlId:s||k})),[k,s]),V=!R&&null!=I&&!1!==I||(0,b.XW)(R,u),H=(0,n.jsx)(p,{...P,type:"switch"===E?"checkbox":E,ref:a,isValid:v,isInvalid:N,disabled:d,as:F});return(0,n.jsx)(m.Z.Provider,{value:Z,children:(0,n.jsx)("div",{style:g,className:t()(w,V&&r,c&&"".concat(r,"-inline"),i&&"".concat(r,"-reverse"),"switch"===E&&l),children:R||(0,n.jsxs)(n.Fragment,{children:[H,V&&(0,n.jsx)(u,{title:C,children:I}),y&&(0,n.jsx)(f,{type:j,tooltip:h,children:y})]})})})}));h.displayName="FormCheck";const y=Object.assign(h,{Input:p,Label:u});s(42391);const j=o.forwardRef(((e,a)=>{let{bsPrefix:s,type:r,size:l,htmlSize:c,id:i,className:d,isValid:f=!1,isInvalid:v=!1,plaintext:p,readOnly:N,as:u="input",...b}=e;const{controlId:h}=(0,o.useContext)(m.Z);return s=(0,x.vE)(s,"form-control"),(0,n.jsx)(u,{...b,type:r,size:c,ref:a,readOnly:N,id:i||h,className:t()(d,p?"".concat(s,"-plaintext"):s,l&&"".concat(s,"-").concat(l),"color"===r&&"".concat(s,"-color"),f&&"is-valid",v&&"is-invalid")})}));j.displayName="FormControl";const w=Object.assign(j,{Feedback:f}),g=o.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...c}=e;return r=(0,x.vE)(r,"form-floating"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...c})}));g.displayName="FormFloating";const C=g,E=o.forwardRef(((e,a)=>{let{controlId:s,as:r="div",...t}=e;const l=(0,o.useMemo)((()=>({controlId:s})),[s]);return(0,n.jsx)(m.Z.Provider,{value:l,children:(0,n.jsx)(r,{...t,ref:a})})}));E.displayName="FormGroup";const I=E;var R=s(53392);const F=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,id:l,...c}=e;const{controlId:i}=(0,o.useContext)(m.Z);return s=(0,x.vE)(s,"form-range"),(0,n.jsx)("input",{...c,type:"range",ref:a,className:t()(r,s),id:l||i})}));F.displayName="FormRange";const P=F,k=o.forwardRef(((e,a)=>{let{bsPrefix:s,size:r,htmlSize:l,className:c,isValid:i=!1,isInvalid:d=!1,id:f,...v}=e;const{controlId:p}=(0,o.useContext)(m.Z);return s=(0,x.vE)(s,"form-select"),(0,n.jsx)("select",{...v,size:l,ref:a,className:t()(c,s,r&&"".concat(s,"-").concat(r),i&&"is-valid",d&&"is-invalid"),id:f||p})}));k.displayName="FormSelect";const Z=k,V=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,as:l="small",muted:c,...o}=e;return s=(0,x.vE)(s,"form-text"),(0,n.jsx)(l,{...o,ref:a,className:t()(r,s,c&&"text-muted")})}));V.displayName="FormText";const H=V,L=o.forwardRef(((e,a)=>(0,n.jsx)(y,{...e,ref:a,type:"switch"})));L.displayName="Switch";const z=Object.assign(L,{Input:y.Input,Label:y.Label}),T=o.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,children:l,controlId:c,label:o,...i}=e;return s=(0,x.vE)(s,"form-floating"),(0,n.jsxs)(I,{ref:a,className:t()(r,s),controlId:c,...i,children:[l,(0,n.jsx)("label",{htmlFor:c,children:o})]})}));T.displayName="FloatingLabel";const M=T,O={_ref:c().any,validated:c().bool,as:c().elementType},S=o.forwardRef(((e,a)=>{let{className:s,validated:r,as:l="form",...c}=e;return(0,n.jsx)(l,{...c,ref:a,className:t()(s,r&&"was-validated")})}));S.displayName="Form",S.propTypes=O;const _=Object.assign(S,{Group:I,Control:w,Floating:C,Check:y,Switch:z,Label:R.Z,Text:H,Range:P,Select:Z,FloatingLabel:M})},84934:(e,a,s)=>{s.d(a,{Z:()=>r});const r=s(72791).createContext({})},53392:(e,a,s)=>{s.d(a,{Z:()=>f});var r=s(81694),t=s.n(r),l=s(72791),c=(s(42391),s(2677)),o=s(84934),n=s(10162),i=s(80184);const d=l.forwardRef(((e,a)=>{let{as:s="label",bsPrefix:r,column:d=!1,visuallyHidden:f=!1,className:m,htmlFor:x,...v}=e;const{controlId:p}=(0,l.useContext)(o.Z);r=(0,n.vE)(r,"form-label");let N="col-form-label";"string"===typeof d&&(N="".concat(N," ").concat(N,"-").concat(d));const u=t()(m,r,f&&"visually-hidden",d&&N);return x=x||p,d?(0,i.jsx)(c.Z,{ref:a,as:"label",className:u,htmlFor:x,...v}):(0,i.jsx)(s,{ref:a,className:u,htmlFor:x,...v})}));d.displayName="FormLabel";const f=d},27472:(e,a,s)=>{s.d(a,{Z:()=>o});var r=s(72791),t=s(81694),l=s.n(t),c=s(80184);const o=e=>r.forwardRef(((a,s)=>(0,c.jsx)("div",{...a,ref:s,className:l()(a.className,e)})))},30203:(e,a,s)=>{s.d(a,{wEH:()=>t});var r=s(89983);function t(e){return(0,r.w_)({tag:"svg",attr:{viewBox:"0 0 448 512"},child:[{tag:"path",attr:{d:"M256 80c0-17.7-14.3-32-32-32s-32 14.3-32 32V224H48c-17.7 0-32 14.3-32 32s14.3 32 32 32H192V432c0 17.7 14.3 32 32 32s32-14.3 32-32V288H400c17.7 0 32-14.3 32-32s-14.3-32-32-32H256V80z"}}]})(e)}},16856:(e,a,s)=>{s.d(a,{I0:()=>t});var r=s(89983);function t(e){return(0,r.w_)({tag:"svg",attr:{viewBox:"0 0 24 24"},child:[{tag:"path",attr:{fill:"none",d:"M0 0h24v24H0V0z"}},{tag:"path",attr:{d:"M14.12 10.47L12 12.59l-2.13-2.12-1.41 1.41L10.59 14l-2.12 2.12 1.41 1.41L12 15.41l2.12 2.12 1.41-1.41L13.41 14l2.12-2.12zM15.5 4l-1-1h-5l-1 1H5v2h14V4zM6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM8 9h8v10H8V9z"}}]})(e)}}}]);
//# sourceMappingURL=6690.a928e03e.chunk.js.map