"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6558],{85657:(e,s,a)=>{a.d(s,{Z:()=>t});a(72791);var r=a(80184);function t(){return(0,r.jsx)("div",{className:"auth__bg-img",children:(0,r.jsxs)("div",{className:"auth-text-section",children:[(0,r.jsx)("h1",{children:(0,r.jsx)("span",{className:"heading1",children:"GP care with a Modern Touch."})}),(0,r.jsx)("p",{className:"heading2",children:"Fast, hassle-free healthcare for the most common medical conditions from the comfort of your home."})]})})}},17505:(e,s,a)=>{a.d(s,{c:()=>l});var r=a(3810),t=a(80184);function l(e){return(0,t.jsx)("div",{className:"error-message-field-generic",children:(0,t.jsx)("p",{className:"my-1",children:e.message?e.message:r.p.SYSTEM_ERROR})})}},82064:(e,s,a)=>{a.d(s,{Z:()=>t});var r=a(72791);const t=()=>{const[e,s]=(0,r.useState)("");return(0,r.useEffect)((()=>{const e=Intl.DateTimeFormat().resolvedOptions().timeZone;s(e)}),[]),e}},36558:(e,s,a)=>{a.r(s),a.d(s,{default:()=>w});var r=a(72791),t=a(89743),l=a(2677),o=a(95070),n=a(36638),i=a(43360),c=a(9897),d=a(78820),m=a(61134),f=a(17505),p=a(57689),x=a(11087),u=a(3810),h=a(59434),N=a(16115),b=a(49739),v=a(85657),y=a(34740),j=a(82064),g=a(80184);function w(){const[e,s]=(0,r.useState)(!1),{isLoading:a}=(0,h.v9)((e=>e.auth)),w=(0,j.Z)(),Z=(0,p.s0)(),C=(0,h.I0)(),{register:I,handleSubmit:P,formState:{errors:R}}=(0,m.cI)(),E=e=>{let{data:s}=e;localStorage.setItem("family_doc_app",JSON.stringify(s))};return(0,g.jsx)("div",{className:"signin-component h-100",children:(0,g.jsxs)(t.Z,{className:"m-0",children:[(0,g.jsx)(l.Z,{sm:12,md:12,lg:7,className:"p-0",children:(0,g.jsx)(v.Z,{})}),(0,g.jsx)(l.Z,{sm:12,md:12,lg:5,className:"signin-col-2 d-flex justify-content-center py-4 bg-white",children:(0,g.jsxs)("div",{className:"signin-content",children:[(0,g.jsx)("div",{className:"d-flex justify-content-center w-100 my-4",children:(0,g.jsx)("img",{src:c.Z.LOGO,alt:"fda-main-logo",className:"img-fluid text-cursor-pointer",onClick:()=>Z(u.m.SIGNIN)})}),(0,g.jsx)(o.Z,{className:"border-0 bg-transparent",children:(0,g.jsx)(o.Z.Body,{children:(0,g.jsxs)(n.Z,{className:"py-3",onSubmit:P((function(e){(0,y.ZK)().then((s=>{const a={email:e.email,password:e.password,deviceId:s||"",deviceTypeId:1,timeZone:w};C((0,N.Ib)({finalData:a,moveToNext:E}))})).catch((e=>{console.error("Error in onSubmit:",e)}))})),children:[(0,g.jsx)("div",{className:"signin-heading text-center",children:"Sign In"}),(0,g.jsx)("p",{className:"text-center mb-5",children:"Please enter your details below to sign into your account."}),(0,g.jsxs)(n.Z.Group,{className:"mb-3",children:[(0,g.jsx)(n.Z.Label,{className:"label-primary",children:"Email"}),(0,g.jsx)(n.Z.Control,{type:"email",name:"email",placeholder:"Email",size:"lg",...I("email",{required:!0,pattern:/^[^@ ]+@[^@ ]+\.[^@ .]{2,}$/})}),R.email&&(0,g.jsx)(f.c,{message:"This Field is Required"})]}),(0,g.jsxs)(n.Z.Group,{className:"position-relative",controlId:"formBasicPassword",children:[(0,g.jsx)(n.Z.Label,{className:"label-primary",children:"Password"}),(0,g.jsx)(n.Z.Control,{type:e?"text":"password",placeholder:"Password",name:"password",size:"lg",...I("password",{required:!0})}),(0,g.jsx)("div",{onClick:()=>s((e=>!e)),className:"eye-icon",children:e?(0,g.jsx)(d.Zju,{size:18}):(0,g.jsx)(d.I0d,{size:18})})]}),R.password&&(0,g.jsx)(f.c,{message:"This Field is Required"}),(0,g.jsxs)("span",{className:"mt-3 d-flex flex-wrap justify-content-between align-items-center",children:[(0,g.jsx)(n.Z.Group,{controlId:"formBasicCheckbox",children:(0,g.jsx)(n.Z.Check,{type:"checkbox",label:"Remember Me",className:"card-internal-text me-2"})}),(0,g.jsx)("span",{className:"forget-pass",children:(0,g.jsx)(x.rU,{to:u.m.FORGETPASSWORD,children:(0,g.jsx)(n.Z.Text,{className:"cursor-pointer",children:"Forget Password?"})})})]}),(0,g.jsx)(i.Z,{className:"w-100 mt-4 ".concat(a&&"disabled"),type:"submit",children:a?(0,g.jsx)(b.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Sign In"}),(0,g.jsx)("span",{className:"d-flex justify-content-center pt-3",children:(0,g.jsx)(x.rU,{to:u.m.SIGNUP,className:"text-decoration-none",children:(0,g.jsx)(n.Z.Text,{className:"cursor-pointer register-patient",children:"Register as a Patient"})})})]})})})]})})]})})}},95070:(e,s,a)=>{a.d(s,{Z:()=>k});var r=a(41418),t=a.n(r),l=a(72791),o=a(10162),n=a(80184);const i=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...i}=e;return r=(0,o.vE)(r,"card-body"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));i.displayName="CardBody";const c=i,d=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...i}=e;return r=(0,o.vE)(r,"card-footer"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));d.displayName="CardFooter";const m=d;var f=a(96040);const p=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:i="div",...c}=e;const d=(0,o.vE)(a,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,n.jsx)(f.Z.Provider,{value:m,children:(0,n.jsx)(i,{ref:s,...c,className:t()(r,d)})})}));p.displayName="CardHeader";const x=p,u=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,variant:l,as:i="img",...c}=e;const d=(0,o.vE)(a,"card-img");return(0,n.jsx)(i,{ref:s,className:t()(l?"".concat(d,"-").concat(l):d,r),...c})}));u.displayName="CardImg";const h=u,N=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...i}=e;return r=(0,o.vE)(r,"card-img-overlay"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));N.displayName="CardImgOverlay";const b=N,v=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="a",...i}=e;return r=(0,o.vE)(r,"card-link"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));v.displayName="CardLink";const y=v;var j=a(27472);const g=(0,j.Z)("h6"),w=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=g,...i}=e;return r=(0,o.vE)(r,"card-subtitle"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));w.displayName="CardSubtitle";const Z=w,C=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="p",...i}=e;return r=(0,o.vE)(r,"card-text"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));C.displayName="CardText";const I=C,P=(0,j.Z)("h5"),R=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=P,...i}=e;return r=(0,o.vE)(r,"card-title"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...i})}));R.displayName="CardTitle";const E=R,F=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,bg:l,text:i,border:d,body:m=!1,children:f,as:p="div",...x}=e;const u=(0,o.vE)(a,"card");return(0,n.jsx)(p,{ref:s,...x,className:t()(r,u,l&&"bg-".concat(l),i&&"text-".concat(i),d&&"border-".concat(d)),children:m?(0,n.jsx)(c,{children:f}):f})}));F.displayName="Card";const k=Object.assign(F,{Img:h,Title:E,Subtitle:Z,Body:c,Link:y,Text:I,Header:x,Footer:m,ImgOverlay:b})},96040:(e,s,a)=>{a.d(s,{Z:()=>t});const r=a(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,s,a)=>{a.d(s,{Ed:()=>l,UI:()=>t,XW:()=>o});var r=a(72791);function t(e,s){let a=0;return r.Children.map(e,(e=>r.isValidElement(e)?s(e,a++):e))}function l(e,s){let a=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&s(e,a++)}))}function o(e,s){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===s))}},36638:(e,s,a)=>{a.d(s,{Z:()=>V});var r=a(41418),t=a.n(r),l=a(52007),o=a.n(l),n=a(72791),i=a(80184);const c={type:o().string,tooltip:o().bool,as:o().elementType},d=n.forwardRef(((e,s)=>{let{as:a="div",className:r,type:l="valid",tooltip:o=!1,...n}=e;return(0,i.jsx)(a,{...n,ref:s,className:t()(r,"".concat(l,"-").concat(o?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=c;const m=d;var f=a(84934),p=a(10162);const x=n.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,className:l,type:o="checkbox",isValid:c=!1,isInvalid:d=!1,as:m="input",...x}=e;const{controlId:u}=(0,n.useContext)(f.Z);return r=(0,p.vE)(r,"form-check-input"),(0,i.jsx)(m,{...x,ref:s,type:o,id:a||u,className:t()(l,r,c&&"is-valid",d&&"is-invalid")})}));x.displayName="FormCheckInput";const u=x,h=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,htmlFor:l,...o}=e;const{controlId:c}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-check-label"),(0,i.jsx)("label",{...o,ref:s,htmlFor:l||c,className:t()(r,a)})}));h.displayName="FormCheckLabel";const N=h;var b=a(11701);const v=n.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,bsSwitchPrefix:l,inline:o=!1,reverse:c=!1,disabled:d=!1,isValid:x=!1,isInvalid:h=!1,feedbackTooltip:v=!1,feedback:y,feedbackType:j,className:g,style:w,title:Z="",type:C="checkbox",label:I,children:P,as:R="input",...E}=e;r=(0,p.vE)(r,"form-check"),l=(0,p.vE)(l,"form-switch");const{controlId:F}=(0,n.useContext)(f.Z),k=(0,n.useMemo)((()=>({controlId:a||F})),[F,a]),O=!P&&null!=I&&!1!==I||(0,b.XW)(P,N),S=(0,i.jsx)(u,{...E,type:"switch"===C?"checkbox":C,ref:s,isValid:x,isInvalid:h,disabled:d,as:R});return(0,i.jsx)(f.Z.Provider,{value:k,children:(0,i.jsx)("div",{style:w,className:t()(g,O&&r,o&&"".concat(r,"-inline"),c&&"".concat(r,"-reverse"),"switch"===C&&l),children:P||(0,i.jsxs)(i.Fragment,{children:[S,O&&(0,i.jsx)(N,{title:Z,children:I}),y&&(0,i.jsx)(m,{type:j,tooltip:v,children:y})]})})})}));v.displayName="FormCheck";const y=Object.assign(v,{Input:u,Label:N});a(42391);const j=n.forwardRef(((e,s)=>{let{bsPrefix:a,type:r,size:l,htmlSize:o,id:c,className:d,isValid:m=!1,isInvalid:x=!1,plaintext:u,readOnly:h,as:N="input",...b}=e;const{controlId:v}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-control"),(0,i.jsx)(N,{...b,type:r,size:o,ref:s,readOnly:h,id:c||v,className:t()(d,u?"".concat(a,"-plaintext"):a,l&&"".concat(a,"-").concat(l),"color"===r&&"".concat(a,"-color"),m&&"is-valid",x&&"is-invalid")})}));j.displayName="FormControl";const g=Object.assign(j,{Feedback:m}),w=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,p.vE)(r,"form-floating"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));w.displayName="FormFloating";const Z=w,C=n.forwardRef(((e,s)=>{let{controlId:a,as:r="div",...t}=e;const l=(0,n.useMemo)((()=>({controlId:a})),[a]);return(0,i.jsx)(f.Z.Provider,{value:l,children:(0,i.jsx)(r,{...t,ref:s})})}));C.displayName="FormGroup";const I=C;var P=a(53392);const R=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,id:l,...o}=e;const{controlId:c}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-range"),(0,i.jsx)("input",{...o,type:"range",ref:s,className:t()(r,a),id:l||c})}));R.displayName="FormRange";const E=R,F=n.forwardRef(((e,s)=>{let{bsPrefix:a,size:r,htmlSize:l,className:o,isValid:c=!1,isInvalid:d=!1,id:m,...x}=e;const{controlId:u}=(0,n.useContext)(f.Z);return a=(0,p.vE)(a,"form-select"),(0,i.jsx)("select",{...x,size:l,ref:s,className:t()(o,a,r&&"".concat(a,"-").concat(r),c&&"is-valid",d&&"is-invalid"),id:m||u})}));F.displayName="FormSelect";const k=F,O=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:l="small",muted:o,...n}=e;return a=(0,p.vE)(a,"form-text"),(0,i.jsx)(l,{...n,ref:s,className:t()(r,a,o&&"text-muted")})}));O.displayName="FormText";const S=O,T=n.forwardRef(((e,s)=>(0,i.jsx)(y,{...e,ref:s,type:"switch"})));T.displayName="Switch";const L=Object.assign(T,{Input:y.Input,Label:y.Label}),z=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,children:l,controlId:o,label:n,...c}=e;return a=(0,p.vE)(a,"form-floating"),(0,i.jsxs)(I,{ref:s,className:t()(r,a),controlId:o,...c,children:[l,(0,i.jsx)("label",{htmlFor:o,children:n})]})}));z.displayName="FloatingLabel";const G=z,_={_ref:o().any,validated:o().bool,as:o().elementType},M=n.forwardRef(((e,s)=>{let{className:a,validated:r,as:l="form",...o}=e;return(0,i.jsx)(l,{...o,ref:s,className:t()(a,r&&"was-validated")})}));M.displayName="Form",M.propTypes=_;const V=Object.assign(M,{Group:I,Control:g,Floating:Z,Check:y,Switch:L,Label:P.Z,Text:S,Range:E,Select:k,FloatingLabel:G})},84934:(e,s,a)=>{a.d(s,{Z:()=>r});const r=a(72791).createContext({})},53392:(e,s,a)=>{a.d(s,{Z:()=>m});var r=a(41418),t=a.n(r),l=a(72791),o=(a(42391),a(2677)),n=a(84934),i=a(10162),c=a(80184);const d=l.forwardRef(((e,s)=>{let{as:a="label",bsPrefix:r,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:p,...x}=e;const{controlId:u}=(0,l.useContext)(n.Z);r=(0,i.vE)(r,"form-label");let h="col-form-label";"string"===typeof d&&(h="".concat(h," ").concat(h,"-").concat(d));const N=t()(f,r,m&&"visually-hidden",d&&h);return p=p||u,d?(0,c.jsx)(o.Z,{ref:s,as:"label",className:N,htmlFor:p,...x}):(0,c.jsx)(a,{ref:s,className:N,htmlFor:p,...x})}));d.displayName="FormLabel";const m=d},27472:(e,s,a)=>{a.d(s,{Z:()=>n});var r=a(72791),t=a(41418),l=a.n(t),o=a(80184);const n=e=>r.forwardRef(((s,a)=>(0,o.jsx)("div",{...s,ref:a,className:l()(s.className,e)})))},49739:(e,s,a)=>{a.d(s,{Z:()=>c});var r=a(72791),t=a(75617),l=a(6707),o=function(){return o=Object.assign||function(e){for(var s,a=1,r=arguments.length;a<r;a++)for(var t in s=arguments[a])Object.prototype.hasOwnProperty.call(s,t)&&(e[t]=s[t]);return e},o.apply(this,arguments)},n=function(e,s){var a={};for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&s.indexOf(r)<0&&(a[r]=e[r]);if(null!=e&&"function"===typeof Object.getOwnPropertySymbols){var t=0;for(r=Object.getOwnPropertySymbols(e);t<r.length;t++)s.indexOf(r[t])<0&&Object.prototype.propertyIsEnumerable.call(e,r[t])&&(a[r[t]]=e[r[t]])}return a},i=(0,l.i)("ClipLoader","0% {transform: rotate(0deg) scale(1)} 50% {transform: rotate(180deg) scale(0.8)} 100% {transform: rotate(360deg) scale(1)}","clip");const c=function(e){var s=e.loading,a=void 0===s||s,l=e.color,c=void 0===l?"#000000":l,d=e.speedMultiplier,m=void 0===d?1:d,f=e.cssOverride,p=void 0===f?{}:f,x=e.size,u=void 0===x?35:x,h=n(e,["loading","color","speedMultiplier","cssOverride","size"]),N=o({background:"transparent !important",width:(0,t.E)(u),height:(0,t.E)(u),borderRadius:"100%",border:"2px solid",borderTopColor:c,borderBottomColor:"transparent",borderLeftColor:c,borderRightColor:c,display:"inline-block",animation:"".concat(i," ").concat(.75/m,"s 0s infinite linear"),animationFillMode:"both"},p);return a?r.createElement("span",o({style:N},h)):null}}}]);
//# sourceMappingURL=6558.c71c857f.chunk.js.map