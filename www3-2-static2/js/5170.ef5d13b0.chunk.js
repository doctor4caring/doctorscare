"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[5170,0],{17505:(e,s,a)=>{a.d(s,{c:()=>l});var r=a(3810),t=a(80184);function l(e){return(0,t.jsx)("div",{className:"error-message-field-generic",children:(0,t.jsx)("p",{className:"mb-1",children:e.message?e.message:r.p.SYSTEM_ERROR})})}},65170:(e,s,a)=>{a.r(s),a.d(s,{default:()=>v});var r=a(72791),t=a(89743),l=a(2677),o=a(95070),i=a(36638),c=a(43360),n=a(69499),d=a(78820),m=a(61134),f=a(17505),p=a(57689),x=a(3810),h=a(59434),u=a(16115),N=a(49739),b=a(80184);function v(){const[e,s]=(0,r.useState)(!1),[a,v]=(0,r.useState)(!1),{isLoading:y}=(0,h.v9)((e=>e.auth)),j=(0,p.s0)(),{register:g,handleSubmit:w,formState:{errors:C}}=(0,m.cI)(),I=(0,h.I0)(),P=e=>{j(e)};return(0,b.jsx)("div",{className:"signin-component h-100",children:(0,b.jsxs)(t.Z,{className:"vh-100 m-0",children:[(0,b.jsx)(l.Z,{sm:12,md:12,lg:7,className:"p-0",children:(0,b.jsx)("div",{className:"bg-img",children:(0,b.jsx)("div",{className:"signin-page",children:(0,b.jsxs)("div",{className:"auth-text-section",style:{padding:"22% 24% 0% 9%"},children:[(0,b.jsx)("h4",{className:"heading1",children:"GP care with a Modern Touch."}),(0,b.jsx)("p",{className:"heading2",children:"Fast, hassle-free healthcare for the most common medical conditions from the comfort of your home."})]})})})}),(0,b.jsx)(l.Z,{sm:12,md:12,lg:5,className:"d-flex align-items-center py-4 h-100 bg-white",children:(0,b.jsxs)("div",{className:"signin-content",children:[(0,b.jsx)("div",{className:"d-flex justify-content-center w-100 my-4",children:(0,b.jsx)("img",{src:n.Z.LOGO,alt:"FAM Doc Logo",className:"img-fluid text-cursor-pointer",onClick:()=>j(x.m.SIGNIN)})}),(0,b.jsx)(o.Z,{className:"border-0 bg-transparent signup-card-mainclass",children:(0,b.jsx)(o.Z.Body,{children:(0,b.jsxs)(i.Z,{className:"p-3",onSubmit:w((function(e){const s={email:e.email,password:e.password};I((0,u.o1)({finalData:s,moveToNext:()=>{j(x.m.OTPCODE,{state:e.email})}}))})),children:[(0,b.jsx)("div",{className:"signin-heading text-center",children:"Sign Up"}),(0,b.jsx)("p",{className:"text-center mb-5",children:"Please enter your details to create your account."}),(0,b.jsxs)(i.Z.Group,{className:"mb-3",children:[(0,b.jsx)(i.Z.Label,{className:"label-primary",children:"Email"}),(0,b.jsx)(i.Z.Control,{type:"email",name:"email",placeholder:"Email",size:"lg",...g("email",{required:!0,pattern:/^[^@ ]+@[^@ ]+\.[^@ .]{2,}$/})}),C.email&&(0,b.jsx)(f.c,{message:"This Field is Required"})]}),(0,b.jsxs)(i.Z.Group,{className:"position-relative",controlId:"formBasicPassword",children:[(0,b.jsx)(i.Z.Label,{className:"label-primary",children:"Password"}),(0,b.jsx)(i.Z.Control,{type:e?"text":"password",placeholder:"Password",name:"password",size:"lg",...g("password",{required:!0})}),(0,b.jsx)("div",{onClick:()=>s((e=>!e)),className:"eye-icon",children:e?(0,b.jsx)(d.Zju,{size:18}):(0,b.jsx)(d.I0d,{size:18})})]}),C.password&&(0,b.jsx)(f.c,{message:"This Field is Required"}),(0,b.jsxs)(i.Z.Group,{className:"my-3 d-flex",controlId:"formBasicCheckbox",children:[(0,b.jsx)(i.Z.Check,{type:"checkbox",className:"card-internal-text me-2",onChange:e=>{const{checked:s}=e.target;v(s)}}),(0,b.jsxs)("p",{style:{fontSize:"0.9rem"},children:["I agree with"," ",(0,b.jsx)("span",{onClick:()=>P(x.m.TERMSANDCONDITION),className:"text-cursor-pointer policies-text text-decoration-underline",children:"Terms and Conditions"})," ","of use and"," ",(0,b.jsx)("span",{onClick:()=>P(x.m.PRIVACYPOLICY),className:"text-cursor-pointer policies-text text-decoration-underline",children:"Privacy Policy"})]})]}),(0,b.jsx)(c.Z,{className:"w-100 ".concat(y&&"disabled"),type:"submit",disabled:!a,children:!0===y?(0,b.jsx)(N.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Sign Up"})]})})})]})})]})})}},95070:(e,s,a)=>{a.d(s,{Z:()=>F});var r=a(81694),t=a.n(r),l=a(72791),o=a(10162),i=a(80184);const c=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...c}=e;return r=(0,o.vE)(r,"card-body"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...c})}));c.displayName="CardBody";const n=c,d=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...c}=e;return r=(0,o.vE)(r,"card-footer"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...c})}));d.displayName="CardFooter";const m=d;var f=a(96040);const p=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:c="div",...n}=e;const d=(0,o.vE)(a,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,i.jsx)(f.Z.Provider,{value:m,children:(0,i.jsx)(c,{ref:s,...n,className:t()(r,d)})})}));p.displayName="CardHeader";const x=p,h=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,variant:l,as:c="img",...n}=e;const d=(0,o.vE)(a,"card-img");return(0,i.jsx)(c,{ref:s,className:t()(l?"".concat(d,"-").concat(l):d,r),...n})}));h.displayName="CardImg";const u=h,N=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...c}=e;return r=(0,o.vE)(r,"card-img-overlay"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...c})}));N.displayName="CardImgOverlay";const b=N,v=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="a",...c}=e;return r=(0,o.vE)(r,"card-link"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...c})}));v.displayName="CardLink";const y=v;var j=a(27472);const g=(0,j.Z)("h6"),w=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=g,...c}=e;return r=(0,o.vE)(r,"card-subtitle"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...c})}));w.displayName="CardSubtitle";const C=w,I=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="p",...c}=e;return r=(0,o.vE)(r,"card-text"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...c})}));I.displayName="CardText";const P=I,Z=(0,j.Z)("h5"),E=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=Z,...c}=e;return r=(0,o.vE)(r,"card-title"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...c})}));E.displayName="CardTitle";const R=E,k=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,bg:l,text:c,border:d,body:m=!1,children:f,as:p="div",...x}=e;const h=(0,o.vE)(a,"card");return(0,i.jsx)(p,{ref:s,...x,className:t()(r,h,l&&"bg-".concat(l),c&&"text-".concat(c),d&&"border-".concat(d)),children:m?(0,i.jsx)(n,{children:f}):f})}));k.displayName="Card";const F=Object.assign(k,{Img:u,Title:R,Subtitle:C,Body:n,Link:y,Text:P,Header:x,Footer:m,ImgOverlay:b})},96040:(e,s,a)=>{a.d(s,{Z:()=>t});const r=a(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,s,a)=>{a.d(s,{Ed:()=>l,UI:()=>t,XW:()=>o});var r=a(72791);function t(e,s){let a=0;return r.Children.map(e,(e=>r.isValidElement(e)?s(e,a++):e))}function l(e,s){let a=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&s(e,a++)}))}function o(e,s){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===s))}},36638:(e,s,a)=>{a.d(s,{Z:()=>B});var r=a(81694),t=a.n(r),l=a(52007),o=a.n(l),i=a(72791),c=a(80184);const n={type:o().string,tooltip:o().bool,as:o().elementType},d=i.forwardRef(((e,s)=>{let{as:a="div",className:r,type:l="valid",tooltip:o=!1,...i}=e;return(0,c.jsx)(a,{...i,ref:s,className:t()(r,"".concat(l,"-").concat(o?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=n;const m=d;var f=a(84934),p=a(10162);const x=i.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,className:l,type:o="checkbox",isValid:n=!1,isInvalid:d=!1,as:m="input",...x}=e;const{controlId:h}=(0,i.useContext)(f.Z);return r=(0,p.vE)(r,"form-check-input"),(0,c.jsx)(m,{...x,ref:s,type:o,id:a||h,className:t()(l,r,n&&"is-valid",d&&"is-invalid")})}));x.displayName="FormCheckInput";const h=x,u=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,htmlFor:l,...o}=e;const{controlId:n}=(0,i.useContext)(f.Z);return a=(0,p.vE)(a,"form-check-label"),(0,c.jsx)("label",{...o,ref:s,htmlFor:l||n,className:t()(r,a)})}));u.displayName="FormCheckLabel";const N=u;var b=a(11701);const v=i.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,bsSwitchPrefix:l,inline:o=!1,reverse:n=!1,disabled:d=!1,isValid:x=!1,isInvalid:u=!1,feedbackTooltip:v=!1,feedback:y,feedbackType:j,className:g,style:w,title:C="",type:I="checkbox",label:P,children:Z,as:E="input",...R}=e;r=(0,p.vE)(r,"form-check"),l=(0,p.vE)(l,"form-switch");const{controlId:k}=(0,i.useContext)(f.Z),F=(0,i.useMemo)((()=>({controlId:a||k})),[k,a]),O=!Z&&null!=P&&!1!==P||(0,b.XW)(Z,N),S=(0,c.jsx)(h,{...R,type:"switch"===I?"checkbox":I,ref:s,isValid:x,isInvalid:u,disabled:d,as:E});return(0,c.jsx)(f.Z.Provider,{value:F,children:(0,c.jsx)("div",{style:w,className:t()(g,O&&r,o&&"".concat(r,"-inline"),n&&"".concat(r,"-reverse"),"switch"===I&&l),children:Z||(0,c.jsxs)(c.Fragment,{children:[S,O&&(0,c.jsx)(N,{title:C,children:P}),y&&(0,c.jsx)(m,{type:j,tooltip:v,children:y})]})})})}));v.displayName="FormCheck";const y=Object.assign(v,{Input:h,Label:N});a(42391);const j=i.forwardRef(((e,s)=>{let{bsPrefix:a,type:r,size:l,htmlSize:o,id:n,className:d,isValid:m=!1,isInvalid:x=!1,plaintext:h,readOnly:u,as:N="input",...b}=e;const{controlId:v}=(0,i.useContext)(f.Z);return a=(0,p.vE)(a,"form-control"),(0,c.jsx)(N,{...b,type:r,size:o,ref:s,readOnly:u,id:n||v,className:t()(d,h?"".concat(a,"-plaintext"):a,l&&"".concat(a,"-").concat(l),"color"===r&&"".concat(a,"-color"),m&&"is-valid",x&&"is-invalid")})}));j.displayName="FormControl";const g=Object.assign(j,{Feedback:m}),w=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,p.vE)(r,"form-floating"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...o})}));w.displayName="FormFloating";const C=w,I=i.forwardRef(((e,s)=>{let{controlId:a,as:r="div",...t}=e;const l=(0,i.useMemo)((()=>({controlId:a})),[a]);return(0,c.jsx)(f.Z.Provider,{value:l,children:(0,c.jsx)(r,{...t,ref:s})})}));I.displayName="FormGroup";const P=I;var Z=a(53392);const E=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,id:l,...o}=e;const{controlId:n}=(0,i.useContext)(f.Z);return a=(0,p.vE)(a,"form-range"),(0,c.jsx)("input",{...o,type:"range",ref:s,className:t()(r,a),id:l||n})}));E.displayName="FormRange";const R=E,k=i.forwardRef(((e,s)=>{let{bsPrefix:a,size:r,htmlSize:l,className:o,isValid:n=!1,isInvalid:d=!1,id:m,...x}=e;const{controlId:h}=(0,i.useContext)(f.Z);return a=(0,p.vE)(a,"form-select"),(0,c.jsx)("select",{...x,size:l,ref:s,className:t()(o,a,r&&"".concat(a,"-").concat(r),n&&"is-valid",d&&"is-invalid"),id:m||h})}));k.displayName="FormSelect";const F=k,O=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:l="small",muted:o,...i}=e;return a=(0,p.vE)(a,"form-text"),(0,c.jsx)(l,{...i,ref:s,className:t()(r,a,o&&"text-muted")})}));O.displayName="FormText";const S=O,T=i.forwardRef(((e,s)=>(0,c.jsx)(y,{...e,ref:s,type:"switch"})));T.displayName="Switch";const L=Object.assign(T,{Input:y.Input,Label:y.Label}),z=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,children:l,controlId:o,label:i,...n}=e;return a=(0,p.vE)(a,"form-floating"),(0,c.jsxs)(P,{ref:s,className:t()(r,a),controlId:o,...n,children:[l,(0,c.jsx)("label",{htmlFor:o,children:i})]})}));z.displayName="FloatingLabel";const M=z,V={_ref:o().any,validated:o().bool,as:o().elementType},G=i.forwardRef(((e,s)=>{let{className:a,validated:r,as:l="form",...o}=e;return(0,c.jsx)(l,{...o,ref:s,className:t()(a,r&&"was-validated")})}));G.displayName="Form",G.propTypes=V;const B=Object.assign(G,{Group:P,Control:g,Floating:C,Check:y,Switch:L,Label:Z.Z,Text:S,Range:R,Select:F,FloatingLabel:M})},84934:(e,s,a)=>{a.d(s,{Z:()=>r});const r=a(72791).createContext({})},53392:(e,s,a)=>{a.d(s,{Z:()=>m});var r=a(81694),t=a.n(r),l=a(72791),o=(a(42391),a(2677)),i=a(84934),c=a(10162),n=a(80184);const d=l.forwardRef(((e,s)=>{let{as:a="label",bsPrefix:r,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:p,...x}=e;const{controlId:h}=(0,l.useContext)(i.Z);r=(0,c.vE)(r,"form-label");let u="col-form-label";"string"===typeof d&&(u="".concat(u," ").concat(u,"-").concat(d));const N=t()(f,r,m&&"visually-hidden",d&&u);return p=p||h,d?(0,n.jsx)(o.Z,{ref:s,as:"label",className:N,htmlFor:p,...x}):(0,n.jsx)(a,{ref:s,className:N,htmlFor:p,...x})}));d.displayName="FormLabel";const m=d},27472:(e,s,a)=>{a.d(s,{Z:()=>i});var r=a(72791),t=a(81694),l=a.n(t),o=a(80184);const i=e=>r.forwardRef(((s,a)=>(0,o.jsx)("div",{...s,ref:a,className:l()(s.className,e)})))},49739:(e,s,a)=>{a.d(s,{Z:()=>n});var r=a(72791),t=a(75617),l=a(6707),o=function(){return o=Object.assign||function(e){for(var s,a=1,r=arguments.length;a<r;a++)for(var t in s=arguments[a])Object.prototype.hasOwnProperty.call(s,t)&&(e[t]=s[t]);return e},o.apply(this,arguments)},i=function(e,s){var a={};for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&s.indexOf(r)<0&&(a[r]=e[r]);if(null!=e&&"function"===typeof Object.getOwnPropertySymbols){var t=0;for(r=Object.getOwnPropertySymbols(e);t<r.length;t++)s.indexOf(r[t])<0&&Object.prototype.propertyIsEnumerable.call(e,r[t])&&(a[r[t]]=e[r[t]])}return a},c=(0,l.i)("ClipLoader","0% {transform: rotate(0deg) scale(1)} 50% {transform: rotate(180deg) scale(0.8)} 100% {transform: rotate(360deg) scale(1)}","clip");const n=function(e){var s=e.loading,a=void 0===s||s,l=e.color,n=void 0===l?"#000000":l,d=e.speedMultiplier,m=void 0===d?1:d,f=e.cssOverride,p=void 0===f?{}:f,x=e.size,h=void 0===x?35:x,u=i(e,["loading","color","speedMultiplier","cssOverride","size"]),N=o({background:"transparent !important",width:(0,t.E)(h),height:(0,t.E)(h),borderRadius:"100%",border:"2px solid",borderTopColor:n,borderBottomColor:"transparent",borderLeftColor:n,borderRightColor:n,display:"inline-block",animation:"".concat(c," ").concat(.75/m,"s 0s infinite linear"),animationFillMode:"both"},p);return a?r.createElement("span",o({style:N},u)):null}}}]);
//# sourceMappingURL=5170.ef5d13b0.chunk.js.map