"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[5861],{17505:(e,s,a)=>{a.d(s,{c:()=>l});var r=a(3810),t=a(80184);function l(e){return(0,t.jsx)("div",{className:"error-message-field-generic",children:(0,t.jsx)("p",{className:"mb-1",children:e.message?e.message:r.p.SYSTEM_ERROR})})}},95861:(e,s,a)=>{a.r(s),a.d(s,{default:()=>g});var r=a(72791),t=a(89743),l=a(2677),o=a(95070),n=a(36638),i=a(43360),c=a(61134),d=a(57689),m=a(11087),f=a(3810),p=a(4053),x=a(39126),u=a(59434),h=a(17505),N=a(78820),v=a(16115),b=a(98148),y=a(49739),j=a(80184);function g(){const[e,s]=(0,r.useState)(0),[a,g]=(0,r.useState)(!1),[w,P]=(0,r.useState)(!1),[C,I]=(0,r.useState)(["","","",""]),[Z,E]=(0,r.useState)(60),[k,S]=(0,r.useState)(null),[O,R]=(0,r.useState)(""),{isLoading:F}=(0,u.v9)((e=>e.auth)),T=(0,d.s0)(),L=(0,u.I0)(),{register:z,handleSubmit:B,formState:{errors:G}}=(0,c.cI)();(0,r.useEffect)((()=>{const e=setInterval((()=>{E((e=>e-1))}),1e3);return S(e),()=>clearInterval(e)}),[]),(0,r.useEffect)((()=>{0===Z&&clearInterval(k)}),[Z,k]);const M=e=>{s(1)},V=()=>{s(2)},_=()=>{T(f.m.SIGNIN)};return(0,j.jsx)("div",{className:"forget-component h-100",children:(0,j.jsxs)(t.Z,{className:"vh-100 m-0",children:[(0,j.jsx)(l.Z,{sm:12,md:12,lg:7,className:"p-0",children:(0,j.jsx)("div",{className:"bg-img2",children:(0,j.jsx)("div",{className:"signin-page",children:(0,j.jsxs)("div",{style:{padding:"22% 44% 22% 9%"},children:[(0,j.jsx)("h4",{className:"heading1",children:"GP care with a Modern Touch."}),(0,j.jsx)("p",{className:"heading2",children:"Fast, hassle-free healthcare for the most common medical conditions from the comfort of your home."})]})})})}),(0,j.jsx)(l.Z,{sm:12,md:12,lg:5,className:"d-flex align-items-center py-4 h-100 bg-white",children:(0,j.jsxs)("div",{className:"signin-content",children:[(0,j.jsx)("div",{className:"d-flex justify-content-center w-100 py-5",children:(0,j.jsx)("img",{src:p.Z.LOGO,alt:"FAM Doc Logo",className:"img-fluid"})}),(0,j.jsx)(o.Z,{className:"border-0 bg-transparent",children:(0,j.jsxs)(o.Z.Body,{children:[0===e?(0,j.jsxs)(n.Z,{className:"p-3",onSubmit:B((function(e){const s={email:e.email};R(e.email),L((0,v.v9)({sendOtpToEmailData:s,moveToNext:M}))})),children:[(0,j.jsx)("div",{className:"signin-heading text-center",children:"Forgot Password"}),(0,j.jsx)("p",{className:"text-center mb-5",children:"Enter your email we will send you a reset link"}),(0,j.jsxs)(n.Z.Group,{className:"mb-3",children:[(0,j.jsx)(n.Z.Label,{className:"label-primary",children:"Email"}),(0,j.jsx)(n.Z.Control,{type:"email",name:"email",placeholder:"Email",size:"lg",...z("email",{required:!0})}),G.email&&(0,j.jsx)(h.c,{message:"This Field is Required"})]}),(0,j.jsx)(i.Z,{className:"w-100 mt-4 ".concat(F&&"disabled"),type:"submit",children:!0===F?(0,j.jsx)(y.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Send Link"}),(0,j.jsx)("div",{className:"text-center pt-4",children:(0,j.jsxs)(m.rU,{to:f.m.SIGNIN,className:"back-sign-in",children:[(0,j.jsx)(x.i1r,{className:"align-items-center arrow-icon",size:25}),"Back To Sign In"]})})]}):"",1===e?(0,j.jsxs)("form",{className:"p-3",onSubmit:B((function(e){const s=e.otp0+e.otp1+e.otp2+e.otp3,a={email:O,otp:s,timeZone:"Asia/Karachi"};L((0,v.Gd)({confirmOtpByEmailData:a,moveToState2:V}))})),children:[(0,j.jsx)("div",{className:"signin-heading text-center",children:"Confirm Your OTP"}),(0,j.jsx)("p",{className:"text-center mb-5",children:"Please enter the code below we\u2019ve sent to your email"}),C.map(((e,s)=>(0,j.jsx)("input",{type:"text",id:"otp".concat(s),name:"otp".concat(s),maxLength:1,value:e,...z("otp".concat(s),{required:!0}),onChange:e=>function(e,s){const a=e.target.value,r=[...C];var t;r[s]=a.replace(/\D/,""),I(r),s<5&&a&&(null===(t=document.getElementById("otp".concat(s+1)))||void 0===t||t.focus())}(e,s),onKeyDown:e=>function(e,s){var a;"Backspace"===e.key&&!C[s]&&s>0&&(null===(a=document.getElementById("otp".concat(s-1)))||void 0===a||a.focus())}(e,s),className:"otp-field me-3 py-1 text-center",style:{width:"20%",fontweight:500,fontSize:"31px"}},s))),(0,j.jsxs)("p",{className:"text-center pt-4 text-black",children:[(0,j.jsx)("span",{className:"text-gray text-cursor-pointer",children:"Resend"})," ","OTP in ",Z," Sec"]}),(0,j.jsx)(i.Z,{className:"w-100 mt-5",type:"submit",children:"Confirm Code"}),(0,j.jsx)("div",{className:"text-center pt-4",children:(0,j.jsxs)(m.rU,{to:f.m.SIGNIN,className:"back-sign-in",children:[(0,j.jsx)(x.i1r,{className:"align-items-center arrow-icon",size:25}),"Back To Sign In"]})})]}):"",2===e?(0,j.jsxs)(n.Z,{className:"p-3",onSubmit:B((function(e){const s={email:O,password:e.password&&e.confirmOldPassword};e.password===e.confirmOldPassword?L((0,v.oh)({finalData:s,moveToState3:_})):(0,b.P_)("Your Password doesn't Match!","error")})),children:[(0,j.jsx)("div",{className:"signin-heading text-center",children:"Create New Password"}),(0,j.jsx)("p",{className:"text-center mb-5",children:"Please create your new password for next time login"}),(0,j.jsxs)(n.Z.Group,{className:" position-relative mb-3",controlId:"formBasicPassword",children:[(0,j.jsx)(n.Z.Label,{className:"label-primary",children:"Password"}),(0,j.jsx)(n.Z.Control,{type:a?"text":"password",placeholder:"Password",name:"password",size:"lg",...z("password",{required:!0})}),(0,j.jsx)("div",{onClick:()=>g((e=>!e)),className:"eye-icon",children:a?(0,j.jsx)(N.Zju,{size:18}):(0,j.jsx)(N.I0d,{size:18})})]}),(0,j.jsxs)(n.Z.Group,{className:" position-relative",controlId:"formBasicPassword1",children:[(0,j.jsx)(n.Z.Label,{className:"label-primary",children:"Confirm Password"}),(0,j.jsx)(n.Z.Control,{type:w?"text":"password",placeholder:"Password",name:"confirmOldPassword",size:"lg",...z("confirmOldPassword",{required:!0})}),(0,j.jsx)("div",{onClick:()=>P((e=>!e)),className:"eye-icon",children:w?(0,j.jsx)(N.Zju,{size:18}):(0,j.jsx)(N.I0d,{size:18})})]}),(0,j.jsx)(i.Z,{className:"w-100 mt-4",type:"submit",children:"Set Password"})]}):""]})})]})})]})})}},95070:(e,s,a)=>{a.d(s,{Z:()=>O});var r=a(81694),t=a.n(r),l=a(72791),o=a(10162),n=a(80184);const i=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...i}=e;return r=(0,o.vE)(r,"card-body"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));i.displayName="CardBody";const c=i,d=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...i}=e;return r=(0,o.vE)(r,"card-footer"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));d.displayName="CardFooter";const m=d;var f=a(96040);const p=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:i="div",...c}=e;const d=(0,o.vE)(a,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,n.jsx)(f.Z.Provider,{value:m,children:(0,n.jsx)(i,{ref:s,...c,className:t()(r,d)})})}));p.displayName="CardHeader";const x=p,u=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,variant:l,as:i="img",...c}=e;const d=(0,o.vE)(a,"card-img");return(0,n.jsx)(i,{ref:s,className:t()(l?"".concat(d,"-").concat(l):d,r),...c})}));u.displayName="CardImg";const h=u,N=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...i}=e;return r=(0,o.vE)(r,"card-img-overlay"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));N.displayName="CardImgOverlay";const v=N,b=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="a",...i}=e;return r=(0,o.vE)(r,"card-link"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));b.displayName="CardLink";const y=b;var j=a(27472);const g=(0,j.Z)("h6"),w=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=g,...i}=e;return r=(0,o.vE)(r,"card-subtitle"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));w.displayName="CardSubtitle";const P=w,C=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="p",...i}=e;return r=(0,o.vE)(r,"card-text"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));C.displayName="CardText";const I=C,Z=(0,j.Z)("h5"),E=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=Z,...i}=e;return r=(0,o.vE)(r,"card-title"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));E.displayName="CardTitle";const k=E,S=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,bg:l,text:i,border:d,body:m=!1,children:f,as:p="div",...x}=e;const u=(0,o.vE)(a,"card");return(0,n.jsx)(p,{ref:s,...x,className:t()(r,u,l&&"bg-".concat(l),i&&"text-".concat(i),d&&"border-".concat(d)),children:m?(0,n.jsx)(c,{children:f}):f})}));S.displayName="Card";const O=Object.assign(S,{Img:h,Title:k,Subtitle:P,Body:c,Link:y,Text:I,Header:x,Footer:m,ImgOverlay:v})},96040:(e,s,a)=>{a.d(s,{Z:()=>t});const r=a(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,s,a)=>{a.d(s,{Ed:()=>l,UI:()=>t,XW:()=>o});var r=a(72791);function t(e,s){let a=0;return r.Children.map(e,(e=>r.isValidElement(e)?s(e,a++):e))}function l(e,s){let a=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&s(e,a++)}))}function o(e,s){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===s))}},36638:(e,s,a)=>{a.d(s,{Z:()=>V});var r=a(81694),t=a.n(r),l=a(52007),o=a.n(l),n=a(72791),i=a(80184);const c={type:o().string,tooltip:o().bool,as:o().elementType},d=n.forwardRef(((e,s)=>{let{as:a="div",className:r,type:l="valid",tooltip:o=!1,...n}=e;return(0,i.jsx)(a,{...n,ref:s,className:t()(r,"".concat(l,"-").concat(o?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=c;const m=d;var f=a(84934),p=a(10162);const x=n.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,className:l,type:o="checkbox",isValid:c=!1,isInvalid:d=!1,as:m="input",...x}=e;const{controlId:u}=(0,n.useContext)(f.Z);return r=(0,p.vE)(r,"form-check-input"),(0,i.jsx)(m,{...x,ref:s,type:o,id:a||u,className:t()(l,r,c&&"is-valid",d&&"is-invalid")})}));x.displayName="FormCheckInput";const u=x,h=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,htmlFor:l,...o}=e;const{controlId:c}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-check-label"),(0,i.jsx)("label",{...o,ref:s,htmlFor:l||c,className:t()(r,a)})}));h.displayName="FormCheckLabel";const N=h;var v=a(11701);const b=n.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,bsSwitchPrefix:l,inline:o=!1,reverse:c=!1,disabled:d=!1,isValid:x=!1,isInvalid:h=!1,feedbackTooltip:b=!1,feedback:y,feedbackType:j,className:g,style:w,title:P="",type:C="checkbox",label:I,children:Z,as:E="input",...k}=e;r=(0,p.vE)(r,"form-check"),l=(0,p.vE)(l,"form-switch");const{controlId:S}=(0,n.useContext)(f.Z),O=(0,n.useMemo)((()=>({controlId:a||S})),[S,a]),R=!Z&&null!=I&&!1!==I||(0,v.XW)(Z,N),F=(0,i.jsx)(u,{...k,type:"switch"===C?"checkbox":C,ref:s,isValid:x,isInvalid:h,disabled:d,as:E});return(0,i.jsx)(f.Z.Provider,{value:O,children:(0,i.jsx)("div",{style:w,className:t()(g,R&&r,o&&"".concat(r,"-inline"),c&&"".concat(r,"-reverse"),"switch"===C&&l),children:Z||(0,i.jsxs)(i.Fragment,{children:[F,R&&(0,i.jsx)(N,{title:P,children:I}),y&&(0,i.jsx)(m,{type:j,tooltip:b,children:y})]})})})}));b.displayName="FormCheck";const y=Object.assign(b,{Input:u,Label:N});a(42391);const j=n.forwardRef(((e,s)=>{let{bsPrefix:a,type:r,size:l,htmlSize:o,id:c,className:d,isValid:m=!1,isInvalid:x=!1,plaintext:u,readOnly:h,as:N="input",...v}=e;const{controlId:b}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-control"),(0,i.jsx)(N,{...v,type:r,size:o,ref:s,readOnly:h,id:c||b,className:t()(d,u?"".concat(a,"-plaintext"):a,l&&"".concat(a,"-").concat(l),"color"===r&&"".concat(a,"-color"),m&&"is-valid",x&&"is-invalid")})}));j.displayName="FormControl";const g=Object.assign(j,{Feedback:m}),w=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,p.vE)(r,"form-floating"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));w.displayName="FormFloating";const P=w,C=n.forwardRef(((e,s)=>{let{controlId:a,as:r="div",...t}=e;const l=(0,n.useMemo)((()=>({controlId:a})),[a]);return(0,i.jsx)(f.Z.Provider,{value:l,children:(0,i.jsx)(r,{...t,ref:s})})}));C.displayName="FormGroup";const I=C;var Z=a(53392);const E=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,id:l,...o}=e;const{controlId:c}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-range"),(0,i.jsx)("input",{...o,type:"range",ref:s,className:t()(r,a),id:l||c})}));E.displayName="FormRange";const k=E,S=n.forwardRef(((e,s)=>{let{bsPrefix:a,size:r,htmlSize:l,className:o,isValid:c=!1,isInvalid:d=!1,id:m,...x}=e;const{controlId:u}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-select"),(0,i.jsx)("select",{...x,size:l,ref:s,className:t()(o,a,r&&"".concat(a,"-").concat(r),c&&"is-valid",d&&"is-invalid"),id:m||u})}));S.displayName="FormSelect";const O=S,R=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:l="small",muted:o,...n}=e;return a=(0,p.vE)(a,"form-text"),(0,i.jsx)(l,{...n,ref:s,className:t()(r,a,o&&"text-muted")})}));R.displayName="FormText";const F=R,T=n.forwardRef(((e,s)=>(0,i.jsx)(y,{...e,ref:s,type:"switch"})));T.displayName="Switch";const L=Object.assign(T,{Input:y.Input,Label:y.Label}),z=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,children:l,controlId:o,label:n,...c}=e;return a=(0,p.vE)(a,"form-floating"),(0,i.jsxs)(I,{ref:s,className:t()(r,a),controlId:o,...c,children:[l,(0,i.jsx)("label",{htmlFor:o,children:n})]})}));z.displayName="FloatingLabel";const B=z,G={_ref:o().any,validated:o().bool,as:o().elementType},M=n.forwardRef(((e,s)=>{let{className:a,validated:r,as:l="form",...o}=e;return(0,i.jsx)(l,{...o,ref:s,className:t()(a,r&&"was-validated")})}));M.displayName="Form",M.propTypes=G;const V=Object.assign(M,{Group:I,Control:g,Floating:P,Check:y,Switch:L,Label:Z.Z,Text:F,Range:k,Select:O,FloatingLabel:B})},84934:(e,s,a)=>{a.d(s,{Z:()=>r});const r=a(72791).createContext({})},53392:(e,s,a)=>{a.d(s,{Z:()=>m});var r=a(81694),t=a.n(r),l=a(72791),o=(a(42391),a(2677)),n=a(84934),i=a(10162),c=a(80184);const d=l.forwardRef(((e,s)=>{let{as:a="label",bsPrefix:r,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:p,...x}=e;const{controlId:u}=(0,l.useContext)(n.Z);r=(0,i.vE)(r,"form-label");let h="col-form-label";"string"===typeof d&&(h="".concat(h," ").concat(h,"-").concat(d));const N=t()(f,r,m&&"visually-hidden",d&&h);return p=p||u,d?(0,c.jsx)(o.Z,{ref:s,as:"label",className:N,htmlFor:p,...x}):(0,c.jsx)(a,{ref:s,className:N,htmlFor:p,...x})}));d.displayName="FormLabel";const m=d},27472:(e,s,a)=>{a.d(s,{Z:()=>n});var r=a(72791),t=a(81694),l=a.n(t),o=a(80184);const n=e=>r.forwardRef(((s,a)=>(0,o.jsx)("div",{...s,ref:a,className:l()(s.className,e)})))},49739:(e,s,a)=>{a.d(s,{Z:()=>c});var r=a(72791),t=a(75617),l=a(6707),o=function(){return o=Object.assign||function(e){for(var s,a=1,r=arguments.length;a<r;a++)for(var t in s=arguments[a])Object.prototype.hasOwnProperty.call(s,t)&&(e[t]=s[t]);return e},o.apply(this,arguments)},n=function(e,s){var a={};for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&s.indexOf(r)<0&&(a[r]=e[r]);if(null!=e&&"function"===typeof Object.getOwnPropertySymbols){var t=0;for(r=Object.getOwnPropertySymbols(e);t<r.length;t++)s.indexOf(r[t])<0&&Object.prototype.propertyIsEnumerable.call(e,r[t])&&(a[r[t]]=e[r[t]])}return a},i=(0,l.i)("ClipLoader","0% {transform: rotate(0deg) scale(1)} 50% {transform: rotate(180deg) scale(0.8)} 100% {transform: rotate(360deg) scale(1)}","clip");const c=function(e){var s=e.loading,a=void 0===s||s,l=e.color,c=void 0===l?"#000000":l,d=e.speedMultiplier,m=void 0===d?1:d,f=e.cssOverride,p=void 0===f?{}:f,x=e.size,u=void 0===x?35:x,h=n(e,["loading","color","speedMultiplier","cssOverride","size"]),N=o({background:"transparent !important",width:(0,t.E)(u),height:(0,t.E)(u),borderRadius:"100%",border:"2px solid",borderTopColor:c,borderBottomColor:"transparent",borderLeftColor:c,borderRightColor:c,display:"inline-block",animation:"".concat(i," ").concat(.75/m,"s 0s infinite linear"),animationFillMode:"both"},p);return a?r.createElement("span",o({style:N},h)):null}}}]);
//# sourceMappingURL=5861.0b265aa0.chunk.js.map