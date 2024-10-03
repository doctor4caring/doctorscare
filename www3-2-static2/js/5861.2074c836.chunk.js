"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[5861],{85657:(e,s,a)=>{a.d(s,{Z:()=>r});a(72791);var t=a(80184);function r(){return(0,t.jsx)("div",{className:"auth__bg-img",children:(0,t.jsxs)("div",{className:"auth-text-section",children:[(0,t.jsx)("h1",{children:(0,t.jsx)("span",{className:"heading1",children:"GP care with a Modern Touch."})}),(0,t.jsx)("p",{className:"heading2",children:"Fast, hassle-free healthcare for the most common medical conditions from the comfort of your home."})]})})}},17505:(e,s,a)=>{a.d(s,{c:()=>o});var t=a(3810),r=a(80184);function o(e){return(0,r.jsx)("div",{className:"error-message-field-generic",children:(0,r.jsx)("p",{className:"my-1",children:e.message?e.message:t.p.SYSTEM_ERROR})})}},82064:(e,s,a)=>{a.d(s,{Z:()=>r});var t=a(72791);const r=()=>{const[e,s]=(0,t.useState)("");return(0,t.useEffect)((()=>{const e=Intl.DateTimeFormat().resolvedOptions().timeZone;s(e)}),[]),e}},95861:(e,s,a)=>{a.r(s),a.d(s,{default:()=>Z});var t=a(72791),r=a(89743),o=a(2677),l=a(95070),n=a(36638),c=a(43360),i=a(61134),d=a(57689),m=a(11087),f=a(3810),p=a(9897),x=a(39126),u=a(59434),h=a(17505),N=a(78820),v=a(16115),b=a(73683),j=a(49739),y=a(85657),g=a(82064),w=a(80184);function Z(){const[e,s]=(0,t.useState)(0),[a,Z]=(0,t.useState)(!1),[C,I]=(0,t.useState)(!1),[P,E]=(0,t.useState)(["","","",""]),[S,k]=(0,t.useState)(300),[O,R]=(0,t.useState)(null),[F,T]=(0,t.useState)(""),L=(0,g.Z)(),{isLoading:z}=(0,u.v9)((e=>e.auth)),B=(0,d.s0)(),G=(0,u.I0)(),{register:M,handleSubmit:_,formState:{errors:D}}=(0,i.cI)();(0,t.useEffect)((()=>{const e=setInterval((()=>{k((e=>e-1))}),1e3);return R(e),()=>clearInterval(e)}),[]),(0,t.useEffect)((()=>{0===S&&clearInterval(O)}),[S,O]);const V=e=>{s(1)},q=()=>{s(2)},H=()=>{B(f.m.SIGNIN)};return(0,w.jsx)("div",{className:"forget-component h-100",children:(0,w.jsxs)(r.Z,{className:"m-0",children:[(0,w.jsx)(o.Z,{sm:12,md:12,lg:7,className:"p-0",children:(0,w.jsx)(y.Z,{})}),(0,w.jsx)(o.Z,{sm:12,md:12,lg:5,className:"signin-col-2 d-flex justify-content-center py-4 bg-white",children:(0,w.jsxs)("div",{className:"signin-content",children:[(0,w.jsx)("div",{className:"d-flex justify-content-center w-100 my-4",children:(0,w.jsx)("img",{src:p.Z.LOGO,alt:"FAM Doc Logo",className:"img-fluid text-cursor-pointer",onClick:()=>B(f.m.SIGNIN)})}),(0,w.jsx)(l.Z,{className:"border-0 bg-transparent",children:(0,w.jsxs)(l.Z.Body,{children:[0===e?(0,w.jsxs)(n.Z,{className:"py-3",onSubmit:_((function(e){const s={email:e.email};T(e.email),G((0,v.v9)({sendOtpToEmailData:s,moveToNext:V}))})),children:[(0,w.jsx)("div",{className:"signin-heading text-center",children:"Forgot Password"}),(0,w.jsx)("p",{className:"text-center mb-5",children:"Enter your email we will send you a reset link"}),(0,w.jsxs)(n.Z.Group,{className:"mb-3",children:[(0,w.jsx)(n.Z.Label,{className:"label-primary",children:"Email"}),(0,w.jsx)(n.Z.Control,{type:"email",name:"email",placeholder:"Email",size:"lg",...M("email",{required:!0})}),D.email&&(0,w.jsx)(h.c,{message:"This Field is Required"})]}),(0,w.jsx)(c.Z,{className:"w-100 mt-4 ".concat(z&&"disabled"),type:"submit",children:!0===z?(0,w.jsx)(j.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Send Link"}),(0,w.jsx)("div",{className:"text-center pt-4",children:(0,w.jsxs)(m.rU,{to:f.m.SIGNIN,className:"back-sign-in",children:[(0,w.jsx)(x.i1r,{className:"align-items-center arrow-icon",size:25}),"Back To Sign In"]})})]}):"",1===e?(0,w.jsxs)("form",{className:"p-3",onSubmit:_((function(e){const s=e.otp0+e.otp1+e.otp2+e.otp3,a={email:F,otp:s,timeZone:L};G((0,v.Gd)({confirmOtpByEmailData:a,moveToState2:q}))})),children:[(0,w.jsx)("div",{className:"signin-heading text-center",children:"Confirm Your OTP"}),(0,w.jsx)("p",{className:"text-center mb-5",children:"Please enter the code below we\u2019ve sent to your email"}),(0,w.jsx)(r.Z,{children:P.map(((e,s)=>(0,w.jsx)(o.Z,{xs:6,sm:3,className:"pb-3",children:(0,w.jsx)("input",{type:"text",id:"otp".concat(s),name:"otp".concat(s),maxLength:1,value:e,...M("otp".concat(s),{required:!0}),onChange:e=>function(e,s){const a=e.target.value,t=[...P];var r;t[s]=a.replace(/\D/,""),E(t),s<5&&a&&(null===(r=document.getElementById("otp".concat(s+1)))||void 0===r||r.focus())}(e,s),onKeyDown:e=>function(e,s){var a;"Backspace"===e.key&&!P[s]&&s>0&&(null===(a=document.getElementById("otp".concat(s-1)))||void 0===a||a.focus())}(e,s),className:"otp-field py-1 text-center"},s)})))}),(0,w.jsxs)("div",{className:"text-center text-black",children:[(0,w.jsx)("button",{type:"button",onClick:()=>{k(300);const e=setInterval((()=>{k((e=>e-1))}),1e3);R(e);const s={email:F};G((0,v.Rv)({resendOtpData:s}))},className:"text-center bg-transparent border-0 text-gray text-cursor-pointer me-1",disabled:0!==S,children:"Resend"}),"OTP in ",(e=>{const s=Math.floor(e/60),a=e%60;return"".concat(String(s).padStart(2,"0"),":").concat(String(a).padStart(2,"0"))})(S)]}),(0,w.jsx)(c.Z,{className:"w-100 mt-5",type:"submit",children:"Confirm Code"}),(0,w.jsx)("div",{className:"text-center pt-4",children:(0,w.jsxs)(m.rU,{to:f.m.SIGNIN,className:"back-sign-in",children:[(0,w.jsx)(x.i1r,{className:"align-items-center arrow-icon",size:25}),"Back To Sign In"]})})]}):"",2===e?(0,w.jsxs)(n.Z,{className:"p-3",onSubmit:_((function(e){const s={email:F,password:e.password&&e.confirmOldPassword};e.password===e.confirmOldPassword?G((0,v.oh)({finalData:s,moveToState3:H})):(0,b.P_)("Your Password doesn't Match!","error")})),children:[(0,w.jsx)("div",{className:"signin-heading text-center",children:"Create New Password"}),(0,w.jsx)("p",{className:"text-center mb-5",children:"Please create your new password for next time login"}),(0,w.jsxs)(n.Z.Group,{className:" position-relative mb-3",controlId:"formBasicPassword",children:[(0,w.jsx)(n.Z.Label,{className:"label-primary",children:"Password"}),(0,w.jsx)(n.Z.Control,{type:a?"text":"password",placeholder:"Password",name:"password",size:"lg",...M("password",{required:!0})}),(0,w.jsx)("div",{onClick:()=>Z((e=>!e)),className:"eye-icon",children:a?(0,w.jsx)(N.Zju,{size:18}):(0,w.jsx)(N.I0d,{size:18})})]}),(0,w.jsxs)(n.Z.Group,{className:" position-relative",controlId:"formBasicPassword1",children:[(0,w.jsx)(n.Z.Label,{className:"label-primary",children:"Confirm Password"}),(0,w.jsx)(n.Z.Control,{type:C?"text":"password",placeholder:"Password",name:"confirmOldPassword",size:"lg",...M("confirmOldPassword",{required:!0})}),(0,w.jsx)("div",{onClick:()=>I((e=>!e)),className:"eye-icon",children:C?(0,w.jsx)(N.Zju,{size:18}):(0,w.jsx)(N.I0d,{size:18})})]}),(0,w.jsx)(c.Z,{className:"w-100 mt-4",type:"submit",children:"Set Password"})]}):""]})})]})})]})})}},95070:(e,s,a)=>{a.d(s,{Z:()=>O});var t=a(41418),r=a.n(t),o=a(72791),l=a(10162),n=a(80184);const c=o.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o="div",...c}=e;return t=(0,l.vE)(t,"card-body"),(0,n.jsx)(o,{ref:s,className:r()(a,t),...c})}));c.displayName="CardBody";const i=c,d=o.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o="div",...c}=e;return t=(0,l.vE)(t,"card-footer"),(0,n.jsx)(o,{ref:s,className:r()(a,t),...c})}));d.displayName="CardFooter";const m=d;var f=a(96040);const p=o.forwardRef(((e,s)=>{let{bsPrefix:a,className:t,as:c="div",...i}=e;const d=(0,l.vE)(a,"card-header"),m=(0,o.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,n.jsx)(f.Z.Provider,{value:m,children:(0,n.jsx)(c,{ref:s,...i,className:r()(t,d)})})}));p.displayName="CardHeader";const x=p,u=o.forwardRef(((e,s)=>{let{bsPrefix:a,className:t,variant:o,as:c="img",...i}=e;const d=(0,l.vE)(a,"card-img");return(0,n.jsx)(c,{ref:s,className:r()(o?"".concat(d,"-").concat(o):d,t),...i})}));u.displayName="CardImg";const h=u,N=o.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o="div",...c}=e;return t=(0,l.vE)(t,"card-img-overlay"),(0,n.jsx)(o,{ref:s,className:r()(a,t),...c})}));N.displayName="CardImgOverlay";const v=N,b=o.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o="a",...c}=e;return t=(0,l.vE)(t,"card-link"),(0,n.jsx)(o,{ref:s,className:r()(a,t),...c})}));b.displayName="CardLink";const j=b;var y=a(27472);const g=(0,y.Z)("h6"),w=o.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o=g,...c}=e;return t=(0,l.vE)(t,"card-subtitle"),(0,n.jsx)(o,{ref:s,className:r()(a,t),...c})}));w.displayName="CardSubtitle";const Z=w,C=o.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o="p",...c}=e;return t=(0,l.vE)(t,"card-text"),(0,n.jsx)(o,{ref:s,className:r()(a,t),...c})}));C.displayName="CardText";const I=C,P=(0,y.Z)("h5"),E=o.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o=P,...c}=e;return t=(0,l.vE)(t,"card-title"),(0,n.jsx)(o,{ref:s,className:r()(a,t),...c})}));E.displayName="CardTitle";const S=E,k=o.forwardRef(((e,s)=>{let{bsPrefix:a,className:t,bg:o,text:c,border:d,body:m=!1,children:f,as:p="div",...x}=e;const u=(0,l.vE)(a,"card");return(0,n.jsx)(p,{ref:s,...x,className:r()(t,u,o&&"bg-".concat(o),c&&"text-".concat(c),d&&"border-".concat(d)),children:m?(0,n.jsx)(i,{children:f}):f})}));k.displayName="Card";const O=Object.assign(k,{Img:h,Title:S,Subtitle:Z,Body:i,Link:j,Text:I,Header:x,Footer:m,ImgOverlay:v})},96040:(e,s,a)=>{a.d(s,{Z:()=>r});const t=a(72791).createContext(null);t.displayName="CardHeaderContext";const r=t},11701:(e,s,a)=>{a.d(s,{Ed:()=>o,UI:()=>r,XW:()=>l});var t=a(72791);function r(e,s){let a=0;return t.Children.map(e,(e=>t.isValidElement(e)?s(e,a++):e))}function o(e,s){let a=0;t.Children.forEach(e,(e=>{t.isValidElement(e)&&s(e,a++)}))}function l(e,s){return t.Children.toArray(e).some((e=>t.isValidElement(e)&&e.type===s))}},36638:(e,s,a)=>{a.d(s,{Z:()=>_});var t=a(41418),r=a.n(t),o=a(52007),l=a.n(o),n=a(72791),c=a(80184);const i={type:l().string,tooltip:l().bool,as:l().elementType},d=n.forwardRef(((e,s)=>{let{as:a="div",className:t,type:o="valid",tooltip:l=!1,...n}=e;return(0,c.jsx)(a,{...n,ref:s,className:r()(t,"".concat(o,"-").concat(l?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=i;const m=d;var f=a(84934),p=a(10162);const x=n.forwardRef(((e,s)=>{let{id:a,bsPrefix:t,className:o,type:l="checkbox",isValid:i=!1,isInvalid:d=!1,as:m="input",...x}=e;const{controlId:u}=(0,n.useContext)(f.Z);return t=(0,p.vE)(t,"form-check-input"),(0,c.jsx)(m,{...x,ref:s,type:l,id:a||u,className:r()(o,t,i&&"is-valid",d&&"is-invalid")})}));x.displayName="FormCheckInput";const u=x,h=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:t,htmlFor:o,...l}=e;const{controlId:i}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-check-label"),(0,c.jsx)("label",{...l,ref:s,htmlFor:o||i,className:r()(t,a)})}));h.displayName="FormCheckLabel";const N=h;var v=a(11701);const b=n.forwardRef(((e,s)=>{let{id:a,bsPrefix:t,bsSwitchPrefix:o,inline:l=!1,reverse:i=!1,disabled:d=!1,isValid:x=!1,isInvalid:h=!1,feedbackTooltip:b=!1,feedback:j,feedbackType:y,className:g,style:w,title:Z="",type:C="checkbox",label:I,children:P,as:E="input",...S}=e;t=(0,p.vE)(t,"form-check"),o=(0,p.vE)(o,"form-switch");const{controlId:k}=(0,n.useContext)(f.Z),O=(0,n.useMemo)((()=>({controlId:a||k})),[k,a]),R=!P&&null!=I&&!1!==I||(0,v.XW)(P,N),F=(0,c.jsx)(u,{...S,type:"switch"===C?"checkbox":C,ref:s,isValid:x,isInvalid:h,disabled:d,as:E});return(0,c.jsx)(f.Z.Provider,{value:O,children:(0,c.jsx)("div",{style:w,className:r()(g,R&&t,l&&"".concat(t,"-inline"),i&&"".concat(t,"-reverse"),"switch"===C&&o),children:P||(0,c.jsxs)(c.Fragment,{children:[F,R&&(0,c.jsx)(N,{title:Z,children:I}),j&&(0,c.jsx)(m,{type:y,tooltip:b,children:j})]})})})}));b.displayName="FormCheck";const j=Object.assign(b,{Input:u,Label:N});a(42391);const y=n.forwardRef(((e,s)=>{let{bsPrefix:a,type:t,size:o,htmlSize:l,id:i,className:d,isValid:m=!1,isInvalid:x=!1,plaintext:u,readOnly:h,as:N="input",...v}=e;const{controlId:b}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-control"),(0,c.jsx)(N,{...v,type:t,size:l,ref:s,readOnly:h,id:i||b,className:r()(d,u?"".concat(a,"-plaintext"):a,o&&"".concat(a,"-").concat(o),"color"===t&&"".concat(a,"-color"),m&&"is-valid",x&&"is-invalid")})}));y.displayName="FormControl";const g=Object.assign(y,{Feedback:m}),w=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:t,as:o="div",...l}=e;return t=(0,p.vE)(t,"form-floating"),(0,c.jsx)(o,{ref:s,className:r()(a,t),...l})}));w.displayName="FormFloating";const Z=w,C=n.forwardRef(((e,s)=>{let{controlId:a,as:t="div",...r}=e;const o=(0,n.useMemo)((()=>({controlId:a})),[a]);return(0,c.jsx)(f.Z.Provider,{value:o,children:(0,c.jsx)(t,{...r,ref:s})})}));C.displayName="FormGroup";const I=C;var P=a(53392);const E=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:t,id:o,...l}=e;const{controlId:i}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-range"),(0,c.jsx)("input",{...l,type:"range",ref:s,className:r()(t,a),id:o||i})}));E.displayName="FormRange";const S=E,k=n.forwardRef(((e,s)=>{let{bsPrefix:a,size:t,htmlSize:o,className:l,isValid:i=!1,isInvalid:d=!1,id:m,...x}=e;const{controlId:u}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-select"),(0,c.jsx)("select",{...x,size:o,ref:s,className:r()(l,a,t&&"".concat(a,"-").concat(t),i&&"is-valid",d&&"is-invalid"),id:m||u})}));k.displayName="FormSelect";const O=k,R=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:t,as:o="small",muted:l,...n}=e;return a=(0,p.vE)(a,"form-text"),(0,c.jsx)(o,{...n,ref:s,className:r()(t,a,l&&"text-muted")})}));R.displayName="FormText";const F=R,T=n.forwardRef(((e,s)=>(0,c.jsx)(j,{...e,ref:s,type:"switch"})));T.displayName="Switch";const L=Object.assign(T,{Input:j.Input,Label:j.Label}),z=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:t,children:o,controlId:l,label:n,...i}=e;return a=(0,p.vE)(a,"form-floating"),(0,c.jsxs)(I,{ref:s,className:r()(t,a),controlId:l,...i,children:[o,(0,c.jsx)("label",{htmlFor:l,children:n})]})}));z.displayName="FloatingLabel";const B=z,G={_ref:l().any,validated:l().bool,as:l().elementType},M=n.forwardRef(((e,s)=>{let{className:a,validated:t,as:o="form",...l}=e;return(0,c.jsx)(o,{...l,ref:s,className:r()(a,t&&"was-validated")})}));M.displayName="Form",M.propTypes=G;const _=Object.assign(M,{Group:I,Control:g,Floating:Z,Check:j,Switch:L,Label:P.Z,Text:F,Range:S,Select:O,FloatingLabel:B})},84934:(e,s,a)=>{a.d(s,{Z:()=>t});const t=a(72791).createContext({})},53392:(e,s,a)=>{a.d(s,{Z:()=>m});var t=a(41418),r=a.n(t),o=a(72791),l=(a(42391),a(2677)),n=a(84934),c=a(10162),i=a(80184);const d=o.forwardRef(((e,s)=>{let{as:a="label",bsPrefix:t,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:p,...x}=e;const{controlId:u}=(0,o.useContext)(n.Z);t=(0,c.vE)(t,"form-label");let h="col-form-label";"string"===typeof d&&(h="".concat(h," ").concat(h,"-").concat(d));const N=r()(f,t,m&&"visually-hidden",d&&h);return p=p||u,d?(0,i.jsx)(l.Z,{ref:s,as:"label",className:N,htmlFor:p,...x}):(0,i.jsx)(a,{ref:s,className:N,htmlFor:p,...x})}));d.displayName="FormLabel";const m=d},27472:(e,s,a)=>{a.d(s,{Z:()=>n});var t=a(72791),r=a(41418),o=a.n(r),l=a(80184);const n=e=>t.forwardRef(((s,a)=>(0,l.jsx)("div",{...s,ref:a,className:o()(s.className,e)})))},49739:(e,s,a)=>{a.d(s,{Z:()=>i});var t=a(72791),r=a(75617),o=a(6707),l=function(){return l=Object.assign||function(e){for(var s,a=1,t=arguments.length;a<t;a++)for(var r in s=arguments[a])Object.prototype.hasOwnProperty.call(s,r)&&(e[r]=s[r]);return e},l.apply(this,arguments)},n=function(e,s){var a={};for(var t in e)Object.prototype.hasOwnProperty.call(e,t)&&s.indexOf(t)<0&&(a[t]=e[t]);if(null!=e&&"function"===typeof Object.getOwnPropertySymbols){var r=0;for(t=Object.getOwnPropertySymbols(e);r<t.length;r++)s.indexOf(t[r])<0&&Object.prototype.propertyIsEnumerable.call(e,t[r])&&(a[t[r]]=e[t[r]])}return a},c=(0,o.i)("ClipLoader","0% {transform: rotate(0deg) scale(1)} 50% {transform: rotate(180deg) scale(0.8)} 100% {transform: rotate(360deg) scale(1)}","clip");const i=function(e){var s=e.loading,a=void 0===s||s,o=e.color,i=void 0===o?"#000000":o,d=e.speedMultiplier,m=void 0===d?1:d,f=e.cssOverride,p=void 0===f?{}:f,x=e.size,u=void 0===x?35:x,h=n(e,["loading","color","speedMultiplier","cssOverride","size"]),N=l({background:"transparent !important",width:(0,r.E)(u),height:(0,r.E)(u),borderRadius:"100%",border:"2px solid",borderTopColor:i,borderBottomColor:"transparent",borderLeftColor:i,borderRightColor:i,display:"inline-block",animation:"".concat(c," ").concat(.75/m,"s 0s infinite linear"),animationFillMode:"both"},p);return a?t.createElement("span",l({style:N},h)):null}}}]);
//# sourceMappingURL=5861.2074c836.chunk.js.map