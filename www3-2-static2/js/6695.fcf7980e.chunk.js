"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6695],{26695:(e,s,a)=>{a.r(s),a.d(s,{default:()=>f});var r=a(72791),t=a(95070),l=a(36638),o=a(43360),c=a(78820),n=a(61134),i=a(16115),d=a(59434),m=a(80184);const f=function(){const e=(0,d.I0)(),[s,a]=(0,r.useState)(!1),[f,x]=(0,r.useState)(!1),[p,u]=(0,r.useState)(!1),{register:N,watch:v,handleSubmit:b,reset:h,formState:{errors:j}}=(0,n.cI)(),w=(0,r.useRef)({});w.current=v("password","");const y=()=>{h()};return(0,m.jsx)("div",{className:"d-flex justify-content-center",children:(0,m.jsx)(t.Z,{className:"account__settings-layout p-5",children:(0,m.jsxs)(t.Z.Body,{className:"p-0",children:[(0,m.jsx)(t.Z.Title,{children:"Account Setting"}),(0,m.jsx)("h5",{className:"mt-3 font-bold",children:"Change password"}),(0,m.jsx)("p",{className:"mt-3 password-description",children:"Use a strong password. Don't use a password from another sites, or something too obvious like your pet's name."}),(0,m.jsxs)(l.Z,{className:"mt-5 d-flex justify-content-center flex-column",onSubmit:b((function(s){const a={password:s.oldPassword,newPassword:s.password};e((0,i.Cp)({finalData:a,moveToNext:y}))})),children:[(0,m.jsxs)(l.Z.Group,{className:"mb-3 position-relative",controlId:"adminOldPass",children:[(0,m.jsx)(l.Z.Label,{className:"fw-bold",children:"Old Password"}),(0,m.jsxs)("div",{className:"",children:[(0,m.jsx)(l.Z.Control,{type:s?"text":"password",placeholder:"Password",name:"oldPassword",size:"lg",...N("oldPassword",{required:!0})}),j.oldPassword&&(0,m.jsx)("p",{className:"text-danger",children:j.oldPassword.message}),(0,m.jsx)("div",{onClick:()=>a((e=>!e)),className:"eye-icon",children:s?(0,m.jsx)(c.Zju,{size:18}):(0,m.jsx)(c.I0d,{size:18})})]})]}),(0,m.jsxs)(l.Z.Group,{className:"mb-4 position-relative",controlId:"adminNewPass",children:[(0,m.jsx)(l.Z.Label,{className:"fw-bold Form-labeling",children:"New Password"}),(0,m.jsx)(l.Z.Control,{type:f?"text":"password",placeholder:"Password",size:"lg",name:"password",...N("password",{required:!0})}),j.password&&(0,m.jsx)("p",{className:"text-danger",children:j.password.message}),(0,m.jsx)("div",{onClick:()=>x((e=>!e)),className:"eye-icon",children:f?(0,m.jsx)(c.Zju,{size:18}):(0,m.jsx)(c.I0d,{size:18})})]}),(0,m.jsxs)(l.Z.Group,{className:"mb-4 position-relative",controlId:"adminConfirmPass",children:[(0,m.jsx)(l.Z.Label,{className:"fw-bold",children:"Confirm Password"}),(0,m.jsx)(l.Z.Control,{className:"Field-Sizing",type:p?"text":"password",placeholder:"Password",name:"confirmPassword",size:"lg",...N("confirmPassword",{validate:e=>e===w.current||"The passwords does not match"})}),j.confirmPassword&&(0,m.jsx)("p",{className:"text-danger",children:j.confirmPassword.message}),(0,m.jsx)("div",{onClick:()=>u((e=>!e)),className:"eye-icon",children:p?(0,m.jsx)(c.Zju,{size:18}):(0,m.jsx)(c.I0d,{size:18})})]}),(0,m.jsx)("div",{className:"d-grid gap-2 setting-save-button",children:(0,m.jsx)(o.Z,{variant:"primary",size:"md",className:"Save-password-button mt-3",type:"submit",children:"Save Password"})})]})]})})})}},95070:(e,s,a)=>{a.d(s,{Z:()=>E});var r=a(41418),t=a.n(r),l=a(72791),o=a(10162),c=a(80184);const n=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-body"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));n.displayName="CardBody";const i=n,d=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-footer"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));d.displayName="CardFooter";const m=d;var f=a(96040);const x=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:n="div",...i}=e;const d=(0,o.vE)(a,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,c.jsx)(f.Z.Provider,{value:m,children:(0,c.jsx)(n,{ref:s,...i,className:t()(r,d)})})}));x.displayName="CardHeader";const p=x,u=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,variant:l,as:n="img",...i}=e;const d=(0,o.vE)(a,"card-img");return(0,c.jsx)(n,{ref:s,className:t()(l?"".concat(d,"-").concat(l):d,r),...i})}));u.displayName="CardImg";const N=u,v=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-img-overlay"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));v.displayName="CardImgOverlay";const b=v,h=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="a",...n}=e;return r=(0,o.vE)(r,"card-link"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));h.displayName="CardLink";const j=h;var w=a(27472);const y=(0,w.Z)("h6"),g=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=y,...n}=e;return r=(0,o.vE)(r,"card-subtitle"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));g.displayName="CardSubtitle";const P=g,C=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="p",...n}=e;return r=(0,o.vE)(r,"card-text"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));C.displayName="CardText";const Z=C,I=(0,w.Z)("h5"),F=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=I,...n}=e;return r=(0,o.vE)(r,"card-title"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));F.displayName="CardTitle";const R=F,k=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,bg:l,text:n,border:d,body:m=!1,children:f,as:x="div",...p}=e;const u=(0,o.vE)(a,"card");return(0,c.jsx)(x,{ref:s,...p,className:t()(r,u,l&&"bg-".concat(l),n&&"text-".concat(n),d&&"border-".concat(d)),children:m?(0,c.jsx)(i,{children:f}):f})}));k.displayName="Card";const E=Object.assign(k,{Img:N,Title:R,Subtitle:P,Body:i,Link:j,Text:Z,Header:p,Footer:m,ImgOverlay:b})},96040:(e,s,a)=>{a.d(s,{Z:()=>t});const r=a(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,s,a)=>{a.d(s,{Ed:()=>l,UI:()=>t,XW:()=>o});var r=a(72791);function t(e,s){let a=0;return r.Children.map(e,(e=>r.isValidElement(e)?s(e,a++):e))}function l(e,s){let a=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&s(e,a++)}))}function o(e,s){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===s))}},36638:(e,s,a)=>{a.d(s,{Z:()=>H});var r=a(41418),t=a.n(r),l=a(52007),o=a.n(l),c=a(72791),n=a(80184);const i={type:o().string,tooltip:o().bool,as:o().elementType},d=c.forwardRef(((e,s)=>{let{as:a="div",className:r,type:l="valid",tooltip:o=!1,...c}=e;return(0,n.jsx)(a,{...c,ref:s,className:t()(r,"".concat(l,"-").concat(o?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=i;const m=d;var f=a(84934),x=a(10162);const p=c.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,className:l,type:o="checkbox",isValid:i=!1,isInvalid:d=!1,as:m="input",...p}=e;const{controlId:u}=(0,c.useContext)(f.Z);return r=(0,x.vE)(r,"form-check-input"),(0,n.jsx)(m,{...p,ref:s,type:o,id:a||u,className:t()(l,r,i&&"is-valid",d&&"is-invalid")})}));p.displayName="FormCheckInput";const u=p,N=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,htmlFor:l,...o}=e;const{controlId:i}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-check-label"),(0,n.jsx)("label",{...o,ref:s,htmlFor:l||i,className:t()(r,a)})}));N.displayName="FormCheckLabel";const v=N;var b=a(11701);const h=c.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,bsSwitchPrefix:l,inline:o=!1,reverse:i=!1,disabled:d=!1,isValid:p=!1,isInvalid:N=!1,feedbackTooltip:h=!1,feedback:j,feedbackType:w,className:y,style:g,title:P="",type:C="checkbox",label:Z,children:I,as:F="input",...R}=e;r=(0,x.vE)(r,"form-check"),l=(0,x.vE)(l,"form-switch");const{controlId:k}=(0,c.useContext)(f.Z),E=(0,c.useMemo)((()=>({controlId:a||k})),[k,a]),S=!I&&null!=Z&&!1!==Z||(0,b.XW)(I,v),z=(0,n.jsx)(u,{...R,type:"switch"===C?"checkbox":C,ref:s,isValid:p,isInvalid:N,disabled:d,as:F});return(0,n.jsx)(f.Z.Provider,{value:E,children:(0,n.jsx)("div",{style:g,className:t()(y,S&&r,o&&"".concat(r,"-inline"),i&&"".concat(r,"-reverse"),"switch"===C&&l),children:I||(0,n.jsxs)(n.Fragment,{children:[z,S&&(0,n.jsx)(v,{title:P,children:Z}),j&&(0,n.jsx)(m,{type:w,tooltip:h,children:j})]})})})}));h.displayName="FormCheck";const j=Object.assign(h,{Input:u,Label:v});a(42391);const w=c.forwardRef(((e,s)=>{let{bsPrefix:a,type:r,size:l,htmlSize:o,id:i,className:d,isValid:m=!1,isInvalid:p=!1,plaintext:u,readOnly:N,as:v="input",...b}=e;const{controlId:h}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-control"),(0,n.jsx)(v,{...b,type:r,size:o,ref:s,readOnly:N,id:i||h,className:t()(d,u?"".concat(a,"-plaintext"):a,l&&"".concat(a,"-").concat(l),"color"===r&&"".concat(a,"-color"),m&&"is-valid",p&&"is-invalid")})}));w.displayName="FormControl";const y=Object.assign(w,{Feedback:m}),g=c.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,x.vE)(r,"form-floating"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...o})}));g.displayName="FormFloating";const P=g,C=c.forwardRef(((e,s)=>{let{controlId:a,as:r="div",...t}=e;const l=(0,c.useMemo)((()=>({controlId:a})),[a]);return(0,n.jsx)(f.Z.Provider,{value:l,children:(0,n.jsx)(r,{...t,ref:s})})}));C.displayName="FormGroup";const Z=C;var I=a(53392);const F=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,id:l,...o}=e;const{controlId:i}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-range"),(0,n.jsx)("input",{...o,type:"range",ref:s,className:t()(r,a),id:l||i})}));F.displayName="FormRange";const R=F,k=c.forwardRef(((e,s)=>{let{bsPrefix:a,size:r,htmlSize:l,className:o,isValid:i=!1,isInvalid:d=!1,id:m,...p}=e;const{controlId:u}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-select"),(0,n.jsx)("select",{...p,size:l,ref:s,className:t()(o,a,r&&"".concat(a,"-").concat(r),i&&"is-valid",d&&"is-invalid"),id:m||u})}));k.displayName="FormSelect";const E=k,S=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:l="small",muted:o,...c}=e;return a=(0,x.vE)(a,"form-text"),(0,n.jsx)(l,{...c,ref:s,className:t()(r,a,o&&"text-muted")})}));S.displayName="FormText";const z=S,T=c.forwardRef(((e,s)=>(0,n.jsx)(j,{...e,ref:s,type:"switch"})));T.displayName="Switch";const L=Object.assign(T,{Input:j.Input,Label:j.Label}),O=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,children:l,controlId:o,label:c,...i}=e;return a=(0,x.vE)(a,"form-floating"),(0,n.jsxs)(Z,{ref:s,className:t()(r,a),controlId:o,...i,children:[l,(0,n.jsx)("label",{htmlFor:o,children:c})]})}));O.displayName="FloatingLabel";const V=O,_={_ref:o().any,validated:o().bool,as:o().elementType},G=c.forwardRef(((e,s)=>{let{className:a,validated:r,as:l="form",...o}=e;return(0,n.jsx)(l,{...o,ref:s,className:t()(a,r&&"was-validated")})}));G.displayName="Form",G.propTypes=_;const H=Object.assign(G,{Group:Z,Control:y,Floating:P,Check:j,Switch:L,Label:I.Z,Text:z,Range:R,Select:E,FloatingLabel:V})},84934:(e,s,a)=>{a.d(s,{Z:()=>r});const r=a(72791).createContext({})},53392:(e,s,a)=>{a.d(s,{Z:()=>m});var r=a(41418),t=a.n(r),l=a(72791),o=(a(42391),a(2677)),c=a(84934),n=a(10162),i=a(80184);const d=l.forwardRef(((e,s)=>{let{as:a="label",bsPrefix:r,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:x,...p}=e;const{controlId:u}=(0,l.useContext)(c.Z);r=(0,n.vE)(r,"form-label");let N="col-form-label";"string"===typeof d&&(N="".concat(N," ").concat(N,"-").concat(d));const v=t()(f,r,m&&"visually-hidden",d&&N);return x=x||u,d?(0,i.jsx)(o.Z,{ref:s,as:"label",className:v,htmlFor:x,...p}):(0,i.jsx)(a,{ref:s,className:v,htmlFor:x,...p})}));d.displayName="FormLabel";const m=d},27472:(e,s,a)=>{a.d(s,{Z:()=>c});var r=a(72791),t=a(41418),l=a.n(t),o=a(80184);const c=e=>r.forwardRef(((s,a)=>(0,o.jsx)("div",{...s,ref:a,className:l()(s.className,e)})))}}]);
//# sourceMappingURL=6695.fcf7980e.chunk.js.map