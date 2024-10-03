"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[9269],{95070:(e,a,s)=>{s.d(a,{Z:()=>Z});var r=s(41418),t=s.n(r),l=s(72791),c=s(10162),n=s(80184);const i=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...i}=e;return r=(0,c.vE)(r,"card-body"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...i})}));i.displayName="CardBody";const o=i,d=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...i}=e;return r=(0,c.vE)(r,"card-footer"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...i})}));d.displayName="CardFooter";const m=d;var f=s(96040);const x=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,as:i="div",...o}=e;const d=(0,c.vE)(s,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,n.jsx)(f.Z.Provider,{value:m,children:(0,n.jsx)(i,{ref:a,...o,className:t()(r,d)})})}));x.displayName="CardHeader";const p=x,N=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,variant:l,as:i="img",...o}=e;const d=(0,c.vE)(s,"card-img");return(0,n.jsx)(i,{ref:a,className:t()(l?"".concat(d,"-").concat(l):d,r),...o})}));N.displayName="CardImg";const v=N,u=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...i}=e;return r=(0,c.vE)(r,"card-img-overlay"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...i})}));u.displayName="CardImgOverlay";const b=u,y=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="a",...i}=e;return r=(0,c.vE)(r,"card-link"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...i})}));y.displayName="CardLink";const h=y;var j=s(27472);const w=(0,j.Z)("h6"),g=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l=w,...i}=e;return r=(0,c.vE)(r,"card-subtitle"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...i})}));g.displayName="CardSubtitle";const C=g,P=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="p",...i}=e;return r=(0,c.vE)(r,"card-text"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...i})}));P.displayName="CardText";const E=P,R=(0,j.Z)("h5"),F=l.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l=R,...i}=e;return r=(0,c.vE)(r,"card-title"),(0,n.jsx)(l,{ref:a,className:t()(s,r),...i})}));F.displayName="CardTitle";const I=F,k=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,bg:l,text:i,border:d,body:m=!1,children:f,as:x="div",...p}=e;const N=(0,c.vE)(s,"card");return(0,n.jsx)(x,{ref:a,...p,className:t()(r,N,l&&"bg-".concat(l),i&&"text-".concat(i),d&&"border-".concat(d)),children:m?(0,n.jsx)(o,{children:f}):f})}));k.displayName="Card";const Z=Object.assign(k,{Img:v,Title:I,Subtitle:C,Body:o,Link:h,Text:E,Header:p,Footer:m,ImgOverlay:b})},96040:(e,a,s)=>{s.d(a,{Z:()=>t});const r=s(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,a,s)=>{s.d(a,{Ed:()=>l,UI:()=>t,XW:()=>c});var r=s(72791);function t(e,a){let s=0;return r.Children.map(e,(e=>r.isValidElement(e)?a(e,s++):e))}function l(e,a){let s=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&a(e,s++)}))}function c(e,a){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===a))}},36638:(e,a,s)=>{s.d(a,{Z:()=>M});var r=s(41418),t=s.n(r),l=s(52007),c=s.n(l),n=s(72791),i=s(80184);const o={type:c().string,tooltip:c().bool,as:c().elementType},d=n.forwardRef(((e,a)=>{let{as:s="div",className:r,type:l="valid",tooltip:c=!1,...n}=e;return(0,i.jsx)(s,{...n,ref:a,className:t()(r,"".concat(l,"-").concat(c?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=o;const m=d;var f=s(84934),x=s(10162);const p=n.forwardRef(((e,a)=>{let{id:s,bsPrefix:r,className:l,type:c="checkbox",isValid:o=!1,isInvalid:d=!1,as:m="input",...p}=e;const{controlId:N}=(0,n.useContext)(f.Z);return r=(0,x.vE)(r,"form-check-input"),(0,i.jsx)(m,{...p,ref:a,type:c,id:s||N,className:t()(l,r,o&&"is-valid",d&&"is-invalid")})}));p.displayName="FormCheckInput";const N=p,v=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,htmlFor:l,...c}=e;const{controlId:o}=(0,n.useContext)(f.Z);return s=(0,x.vE)(s,"form-check-label"),(0,i.jsx)("label",{...c,ref:a,htmlFor:l||o,className:t()(r,s)})}));v.displayName="FormCheckLabel";const u=v;var b=s(11701);const y=n.forwardRef(((e,a)=>{let{id:s,bsPrefix:r,bsSwitchPrefix:l,inline:c=!1,reverse:o=!1,disabled:d=!1,isValid:p=!1,isInvalid:v=!1,feedbackTooltip:y=!1,feedback:h,feedbackType:j,className:w,style:g,title:C="",type:P="checkbox",label:E,children:R,as:F="input",...I}=e;r=(0,x.vE)(r,"form-check"),l=(0,x.vE)(l,"form-switch");const{controlId:k}=(0,n.useContext)(f.Z),Z=(0,n.useMemo)((()=>({controlId:s||k})),[k,s]),L=!R&&null!=E&&!1!==E||(0,b.XW)(R,u),T=(0,i.jsx)(N,{...I,type:"switch"===P?"checkbox":P,ref:a,isValid:p,isInvalid:v,disabled:d,as:F});return(0,i.jsx)(f.Z.Provider,{value:Z,children:(0,i.jsx)("div",{style:g,className:t()(w,L&&r,c&&"".concat(r,"-inline"),o&&"".concat(r,"-reverse"),"switch"===P&&l),children:R||(0,i.jsxs)(i.Fragment,{children:[T,L&&(0,i.jsx)(u,{title:C,children:E}),h&&(0,i.jsx)(m,{type:j,tooltip:y,children:h})]})})})}));y.displayName="FormCheck";const h=Object.assign(y,{Input:N,Label:u});s(42391);const j=n.forwardRef(((e,a)=>{let{bsPrefix:s,type:r,size:l,htmlSize:c,id:o,className:d,isValid:m=!1,isInvalid:p=!1,plaintext:N,readOnly:v,as:u="input",...b}=e;const{controlId:y}=(0,n.useContext)(f.Z);return s=(0,x.vE)(s,"form-control"),(0,i.jsx)(u,{...b,type:r,size:c,ref:a,readOnly:v,id:o||y,className:t()(d,N?"".concat(s,"-plaintext"):s,l&&"".concat(s,"-").concat(l),"color"===r&&"".concat(s,"-color"),m&&"is-valid",p&&"is-invalid")})}));j.displayName="FormControl";const w=Object.assign(j,{Feedback:m}),g=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:r,as:l="div",...c}=e;return r=(0,x.vE)(r,"form-floating"),(0,i.jsx)(l,{ref:a,className:t()(s,r),...c})}));g.displayName="FormFloating";const C=g,P=n.forwardRef(((e,a)=>{let{controlId:s,as:r="div",...t}=e;const l=(0,n.useMemo)((()=>({controlId:s})),[s]);return(0,i.jsx)(f.Z.Provider,{value:l,children:(0,i.jsx)(r,{...t,ref:a})})}));P.displayName="FormGroup";const E=P;var R=s(53392);const F=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,id:l,...c}=e;const{controlId:o}=(0,n.useContext)(f.Z);return s=(0,x.vE)(s,"form-range"),(0,i.jsx)("input",{...c,type:"range",ref:a,className:t()(r,s),id:l||o})}));F.displayName="FormRange";const I=F,k=n.forwardRef(((e,a)=>{let{bsPrefix:s,size:r,htmlSize:l,className:c,isValid:o=!1,isInvalid:d=!1,id:m,...p}=e;const{controlId:N}=(0,n.useContext)(f.Z);return s=(0,x.vE)(s,"form-select"),(0,i.jsx)("select",{...p,size:l,ref:a,className:t()(c,s,r&&"".concat(s,"-").concat(r),o&&"is-valid",d&&"is-invalid"),id:m||N})}));k.displayName="FormSelect";const Z=k,L=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,as:l="small",muted:c,...n}=e;return s=(0,x.vE)(s,"form-text"),(0,i.jsx)(l,{...n,ref:a,className:t()(r,s,c&&"text-muted")})}));L.displayName="FormText";const T=L,O=n.forwardRef(((e,a)=>(0,i.jsx)(h,{...e,ref:a,type:"switch"})));O.displayName="Switch";const S=Object.assign(O,{Input:h.Input,Label:h.Label}),V=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,children:l,controlId:c,label:n,...o}=e;return s=(0,x.vE)(s,"form-floating"),(0,i.jsxs)(E,{ref:a,className:t()(r,s),controlId:c,...o,children:[l,(0,i.jsx)("label",{htmlFor:c,children:n})]})}));V.displayName="FloatingLabel";const z=V,H={_ref:c().any,validated:c().bool,as:c().elementType},_=n.forwardRef(((e,a)=>{let{className:s,validated:r,as:l="form",...c}=e;return(0,i.jsx)(l,{...c,ref:a,className:t()(s,r&&"was-validated")})}));_.displayName="Form",_.propTypes=H;const M=Object.assign(_,{Group:E,Control:w,Floating:C,Check:h,Switch:S,Label:R.Z,Text:T,Range:I,Select:Z,FloatingLabel:z})},84934:(e,a,s)=>{s.d(a,{Z:()=>r});const r=s(72791).createContext({})},53392:(e,a,s)=>{s.d(a,{Z:()=>m});var r=s(41418),t=s.n(r),l=s(72791),c=(s(42391),s(2677)),n=s(84934),i=s(10162),o=s(80184);const d=l.forwardRef(((e,a)=>{let{as:s="label",bsPrefix:r,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:x,...p}=e;const{controlId:N}=(0,l.useContext)(n.Z);r=(0,i.vE)(r,"form-label");let v="col-form-label";"string"===typeof d&&(v="".concat(v," ").concat(v,"-").concat(d));const u=t()(f,r,m&&"visually-hidden",d&&v);return x=x||N,d?(0,o.jsx)(c.Z,{ref:a,as:"label",className:u,htmlFor:x,...p}):(0,o.jsx)(s,{ref:a,className:u,htmlFor:x,...p})}));d.displayName="FormLabel";const m=d},8116:(e,a,s)=>{s.d(a,{Z:()=>b});var r=s(41418),t=s.n(r),l=s(72791),c=s(10162),n=s(16445),i=s(80184);const o=l.forwardRef(((e,a)=>{let{active:s=!1,disabled:r=!1,className:l,style:c,activeLabel:o="(current)",children:d,linkStyle:m,linkClassName:f,...x}=e;const p=s||r?"span":n.Z;return(0,i.jsx)("li",{ref:a,style:c,className:t()(l,"page-item",{active:s,disabled:r}),children:(0,i.jsxs)(p,{className:t()("page-link",f),style:m,...x,children:[d,s&&o&&(0,i.jsx)("span",{className:"visually-hidden",children:o})]})})}));o.displayName="PageItem";const d=o;function m(e,a){let s=arguments.length>2&&void 0!==arguments[2]?arguments[2]:e;const r=l.forwardRef(((e,r)=>{let{children:t,...l}=e;return(0,i.jsxs)(o,{...l,ref:r,children:[(0,i.jsx)("span",{"aria-hidden":"true",children:t||a}),(0,i.jsx)("span",{className:"visually-hidden",children:s})]})}));return r.displayName=e,r}const f=m("First","\xab"),x=m("Prev","\u2039","Previous"),p=m("Ellipsis","\u2026","More"),N=m("Next","\u203a"),v=m("Last","\xbb"),u=l.forwardRef(((e,a)=>{let{bsPrefix:s,className:r,size:l,...n}=e;const o=(0,c.vE)(s,"pagination");return(0,i.jsx)("ul",{ref:a,...n,className:t()(r,o,l&&"".concat(o,"-").concat(l))})}));u.displayName="Pagination";const b=Object.assign(u,{First:f,Prev:x,Ellipsis:p,Item:d,Next:N,Last:v})}}]);
//# sourceMappingURL=9269.b3a8651c.chunk.js.map