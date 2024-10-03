"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[4962],{64962:(e,s,a)=>{a.r(s),a.d(s,{default:()=>p});var r=a(72791),t=a(95070),l=a(89743),o=a(36638),c=a(2677),n=a(43360),i=a(78820),d=a(61134),m=a(16115),f=a(59434),x=a(80184);const p=function(){const e=(0,f.I0)(),[s,a]=(0,r.useState)(!1),[p,N]=(0,r.useState)(!1),[u,h]=(0,r.useState)(!1),{register:v,watch:b,handleSubmit:j,reset:y,formState:{errors:w}}=(0,d.cI)(),g=(0,r.useRef)({});g.current=b("password","");const P=()=>{y()};return(0,x.jsx)("div",{className:"d-flex justify-content-center Setting-Main-Class",children:(0,x.jsx)(t.Z,{style:{width:"50%"},className:"setting_submain",children:(0,x.jsxs)(t.Z.Body,{className:"p-0",children:[(0,x.jsxs)(t.Z.Title,{className:"account-setting  text-center mt-5",children:["Account Setting",(0,x.jsx)("h5",{className:"fw-bold mt-3 changepassword-size",children:"Change password"}),(0,x.jsx)("p",{className:"Password-text",style:{color:"#999999"},children:"Use a strong password. Don\u2019t use a password from another sites, or something too obvious like your pet\u2019s name."})]}),(0,x.jsx)(l.Z,{className:"mt-5 Password-Input-Spacing",children:(0,x.jsx)(o.Z,{className:"mt-5 d-flex justify-content-center",onSubmit:j((function(s){const a={password:s.oldPassword,newPassword:s.password};e((0,m.Cp)({finalData:a,moveToNext:P}))})),children:(0,x.jsxs)(c.Z,{lg:8,children:[(0,x.jsxs)(o.Z.Group,{className:"mb-3 position-relative",controlId:"formBasicEmail",children:[(0,x.jsx)(o.Z.Label,{className:"fw-bold Form-labeling",style:{color:"#1A1A1A"},children:"Old Password"}),(0,x.jsxs)("div",{className:"d-flex justify-content-center",children:[(0,x.jsx)(o.Z.Control,{className:"Field-Sizing",type:s?"text":"password",placeholder:"Password",name:"oldPassword",size:"lg",...v("oldPassword",{required:!0})}),w.oldPassword&&(0,x.jsx)("p",{className:"text-danger",children:w.oldPassword.message}),(0,x.jsx)("div",{onClick:()=>a((e=>!e)),className:"eye-icon",children:s?(0,x.jsx)(i.Zju,{size:18}):(0,x.jsx)(i.I0d,{size:18})})]})]}),(0,x.jsxs)(o.Z.Group,{className:"mb-4 position-relative",controlId:"formBasicEmail",children:[(0,x.jsx)(o.Z.Label,{className:"fw-bold Form-labeling",style:{color:"#1A1A1A"},children:"New Password"}),(0,x.jsxs)("div",{className:"d-flex justify-content-center",children:[(0,x.jsx)(o.Z.Control,{className:"Field-Sizing",type:p?"text":"password",placeholder:"Password",name:"password",...v("password",{required:!0})}),w.password&&(0,x.jsx)("p",{className:"text-danger",children:w.password.message}),(0,x.jsx)("div",{onClick:()=>N((e=>!e)),className:"eye-icon",children:p?(0,x.jsx)(i.Zju,{size:18}):(0,x.jsx)(i.I0d,{size:18})})]})]}),(0,x.jsxs)(o.Z.Group,{className:"mb-4 position-relative",controlId:"formBasicEmail",children:[(0,x.jsx)(o.Z.Label,{className:"fw-bold Confirm-Password Form-labeling",style:{color:"#1A1A1A"},children:"Confirm Password"}),(0,x.jsxs)("div",{className:"d-flex justify-content-center",children:[(0,x.jsx)(o.Z.Control,{className:"Field-Sizing",type:u?"text":"password",placeholder:"Password",name:"confirmPassword",size:"lg",...v("confirmPassword",{validate:e=>e===g.current||"The passwords does not match"})}),w.confirmPassword&&(0,x.jsx)("p",{className:"text-danger",children:w.confirmPassword.message}),(0,x.jsx)("div",{onClick:()=>h((e=>!e)),className:"eye-icon",children:u?(0,x.jsx)(i.Zju,{size:18}):(0,x.jsx)(i.I0d,{size:18})})]})]}),(0,x.jsx)("div",{className:"d-grid gap-2 setting-save-button",children:(0,x.jsx)(n.Z,{variant:"primary",size:"lg",className:"Save-password-button mt-3",type:"submit",children:"Save Password"})})]})})})]})})})}},95070:(e,s,a)=>{a.d(s,{Z:()=>k});var r=a(81694),t=a.n(r),l=a(72791),o=a(10162),c=a(80184);const n=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-body"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));n.displayName="CardBody";const i=n,d=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-footer"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));d.displayName="CardFooter";const m=d;var f=a(96040);const x=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:n="div",...i}=e;const d=(0,o.vE)(a,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,c.jsx)(f.Z.Provider,{value:m,children:(0,c.jsx)(n,{ref:s,...i,className:t()(r,d)})})}));x.displayName="CardHeader";const p=x,N=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,variant:l,as:n="img",...i}=e;const d=(0,o.vE)(a,"card-img");return(0,c.jsx)(n,{ref:s,className:t()(l?"".concat(d,"-").concat(l):d,r),...i})}));N.displayName="CardImg";const u=N,h=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...n}=e;return r=(0,o.vE)(r,"card-img-overlay"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));h.displayName="CardImgOverlay";const v=h,b=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="a",...n}=e;return r=(0,o.vE)(r,"card-link"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));b.displayName="CardLink";const j=b;var y=a(27472);const w=(0,y.Z)("h6"),g=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=w,...n}=e;return r=(0,o.vE)(r,"card-subtitle"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));g.displayName="CardSubtitle";const P=g,C=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="p",...n}=e;return r=(0,o.vE)(r,"card-text"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));C.displayName="CardText";const Z=C,I=(0,y.Z)("h5"),F=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=I,...n}=e;return r=(0,o.vE)(r,"card-title"),(0,c.jsx)(l,{ref:s,className:t()(a,r),...n})}));F.displayName="CardTitle";const E=F,R=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,bg:l,text:n,border:d,body:m=!1,children:f,as:x="div",...p}=e;const N=(0,o.vE)(a,"card");return(0,c.jsx)(x,{ref:s,...p,className:t()(r,N,l&&"bg-".concat(l),n&&"text-".concat(n),d&&"border-".concat(d)),children:m?(0,c.jsx)(i,{children:f}):f})}));R.displayName="Card";const k=Object.assign(R,{Img:u,Title:E,Subtitle:P,Body:i,Link:j,Text:Z,Header:p,Footer:m,ImgOverlay:v})},96040:(e,s,a)=>{a.d(s,{Z:()=>t});const r=a(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},11701:(e,s,a)=>{a.d(s,{Ed:()=>l,UI:()=>t,XW:()=>o});var r=a(72791);function t(e,s){let a=0;return r.Children.map(e,(e=>r.isValidElement(e)?s(e,a++):e))}function l(e,s){let a=0;r.Children.forEach(e,(e=>{r.isValidElement(e)&&s(e,a++)}))}function o(e,s){return r.Children.toArray(e).some((e=>r.isValidElement(e)&&e.type===s))}},36638:(e,s,a)=>{a.d(s,{Z:()=>_});var r=a(81694),t=a.n(r),l=a(52007),o=a.n(l),c=a(72791),n=a(80184);const i={type:o().string,tooltip:o().bool,as:o().elementType},d=c.forwardRef(((e,s)=>{let{as:a="div",className:r,type:l="valid",tooltip:o=!1,...c}=e;return(0,n.jsx)(a,{...c,ref:s,className:t()(r,"".concat(l,"-").concat(o?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=i;const m=d;var f=a(84934),x=a(10162);const p=c.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,className:l,type:o="checkbox",isValid:i=!1,isInvalid:d=!1,as:m="input",...p}=e;const{controlId:N}=(0,c.useContext)(f.Z);return r=(0,x.vE)(r,"form-check-input"),(0,n.jsx)(m,{...p,ref:s,type:o,id:a||N,className:t()(l,r,i&&"is-valid",d&&"is-invalid")})}));p.displayName="FormCheckInput";const N=p,u=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,htmlFor:l,...o}=e;const{controlId:i}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-check-label"),(0,n.jsx)("label",{...o,ref:s,htmlFor:l||i,className:t()(r,a)})}));u.displayName="FormCheckLabel";const h=u;var v=a(11701);const b=c.forwardRef(((e,s)=>{let{id:a,bsPrefix:r,bsSwitchPrefix:l,inline:o=!1,reverse:i=!1,disabled:d=!1,isValid:p=!1,isInvalid:u=!1,feedbackTooltip:b=!1,feedback:j,feedbackType:y,className:w,style:g,title:P="",type:C="checkbox",label:Z,children:I,as:F="input",...E}=e;r=(0,x.vE)(r,"form-check"),l=(0,x.vE)(l,"form-switch");const{controlId:R}=(0,c.useContext)(f.Z),k=(0,c.useMemo)((()=>({controlId:a||R})),[R,a]),S=!I&&null!=Z&&!1!==Z||(0,v.XW)(I,h),z=(0,n.jsx)(N,{...E,type:"switch"===C?"checkbox":C,ref:s,isValid:p,isInvalid:u,disabled:d,as:F});return(0,n.jsx)(f.Z.Provider,{value:k,children:(0,n.jsx)("div",{style:g,className:t()(w,S&&r,o&&"".concat(r,"-inline"),i&&"".concat(r,"-reverse"),"switch"===C&&l),children:I||(0,n.jsxs)(n.Fragment,{children:[z,S&&(0,n.jsx)(h,{title:P,children:Z}),j&&(0,n.jsx)(m,{type:y,tooltip:b,children:j})]})})})}));b.displayName="FormCheck";const j=Object.assign(b,{Input:N,Label:h});a(42391);const y=c.forwardRef(((e,s)=>{let{bsPrefix:a,type:r,size:l,htmlSize:o,id:i,className:d,isValid:m=!1,isInvalid:p=!1,plaintext:N,readOnly:u,as:h="input",...v}=e;const{controlId:b}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-control"),(0,n.jsx)(h,{...v,type:r,size:o,ref:s,readOnly:u,id:i||b,className:t()(d,N?"".concat(a,"-plaintext"):a,l&&"".concat(a,"-").concat(l),"color"===r&&"".concat(a,"-color"),m&&"is-valid",p&&"is-invalid")})}));y.displayName="FormControl";const w=Object.assign(y,{Feedback:m}),g=c.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,x.vE)(r,"form-floating"),(0,n.jsx)(l,{ref:s,className:t()(a,r),...o})}));g.displayName="FormFloating";const P=g,C=c.forwardRef(((e,s)=>{let{controlId:a,as:r="div",...t}=e;const l=(0,c.useMemo)((()=>({controlId:a})),[a]);return(0,n.jsx)(f.Z.Provider,{value:l,children:(0,n.jsx)(r,{...t,ref:s})})}));C.displayName="FormGroup";const Z=C;var I=a(53392);const F=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,id:l,...o}=e;const{controlId:i}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-range"),(0,n.jsx)("input",{...o,type:"range",ref:s,className:t()(r,a),id:l||i})}));F.displayName="FormRange";const E=F,R=c.forwardRef(((e,s)=>{let{bsPrefix:a,size:r,htmlSize:l,className:o,isValid:i=!1,isInvalid:d=!1,id:m,...p}=e;const{controlId:N}=(0,c.useContext)(f.Z);return a=(0,x.vE)(a,"form-select"),(0,n.jsx)("select",{...p,size:l,ref:s,className:t()(o,a,r&&"".concat(a,"-").concat(r),i&&"is-valid",d&&"is-invalid"),id:m||N})}));R.displayName="FormSelect";const k=R,S=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:l="small",muted:o,...c}=e;return a=(0,x.vE)(a,"form-text"),(0,n.jsx)(l,{...c,ref:s,className:t()(r,a,o&&"text-muted")})}));S.displayName="FormText";const z=S,T=c.forwardRef(((e,s)=>(0,n.jsx)(j,{...e,ref:s,type:"switch"})));T.displayName="Switch";const L=Object.assign(T,{Input:j.Input,Label:j.Label}),A=c.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,children:l,controlId:o,label:c,...i}=e;return a=(0,x.vE)(a,"form-floating"),(0,n.jsxs)(Z,{ref:s,className:t()(r,a),controlId:o,...i,children:[l,(0,n.jsx)("label",{htmlFor:o,children:c})]})}));A.displayName="FloatingLabel";const O=A,V={_ref:o().any,validated:o().bool,as:o().elementType},B=c.forwardRef(((e,s)=>{let{className:a,validated:r,as:l="form",...o}=e;return(0,n.jsx)(l,{...o,ref:s,className:t()(a,r&&"was-validated")})}));B.displayName="Form",B.propTypes=V;const _=Object.assign(B,{Group:Z,Control:w,Floating:P,Check:j,Switch:L,Label:I.Z,Text:z,Range:E,Select:k,FloatingLabel:O})},84934:(e,s,a)=>{a.d(s,{Z:()=>r});const r=a(72791).createContext({})},53392:(e,s,a)=>{a.d(s,{Z:()=>m});var r=a(81694),t=a.n(r),l=a(72791),o=(a(42391),a(2677)),c=a(84934),n=a(10162),i=a(80184);const d=l.forwardRef(((e,s)=>{let{as:a="label",bsPrefix:r,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:x,...p}=e;const{controlId:N}=(0,l.useContext)(c.Z);r=(0,n.vE)(r,"form-label");let u="col-form-label";"string"===typeof d&&(u="".concat(u," ").concat(u,"-").concat(d));const h=t()(f,r,m&&"visually-hidden",d&&u);return x=x||N,d?(0,i.jsx)(o.Z,{ref:s,as:"label",className:h,htmlFor:x,...p}):(0,i.jsx)(a,{ref:s,className:h,htmlFor:x,...p})}));d.displayName="FormLabel";const m=d},27472:(e,s,a)=>{a.d(s,{Z:()=>c});var r=a(72791),t=a(81694),l=a.n(t),o=a(80184);const c=e=>r.forwardRef(((s,a)=>(0,o.jsx)("div",{...s,ref:a,className:l()(s.className,e)})))}}]);
//# sourceMappingURL=4962.63fa4470.chunk.js.map