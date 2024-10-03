"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6933],{14045:(e,s,a)=>{a.d(s,{Z:()=>l});var r=a(88135),t=a(80184);function l(e){let{children:s,...a}=e;const{handleClose:l,show:n,title:i,className:o}=a;return(0,t.jsx)("div",{children:(0,t.jsxs)(r.Z,{show:n,onHide:l,className:o,backdrop:"static",children:[(0,t.jsx)(r.Z.Header,{className:"py-3",closeButton:!0,children:(0,t.jsx)(r.Z.Title,{className:"modalTitle",children:(0,t.jsx)("span",{className:"font-weight-600",children:i})})}),(0,t.jsx)(r.Z.Body,{children:s})]})})}},86933:(e,s,a)=>{a.r(s),a.d(s,{default:()=>E});var r=a(72791),t=a(95070),l=a(11087),n=a(84373),i=a(3810),o=a(43360),c=a(53392),d=a(59434),m=a(65764),u=a(53473),x=a(9085),v=a(49739),p=a(73683),f=a(57689),h=a(14045),N=a(65426),j=a(80184);const b=(0,u.J)("pk_live_51NS6LFJQrjlyogPP8wq3kFDFZOprir0PwWPucUF7VCc9WxEb2uAs6lDskTBrnzHK349ConYGh6zVQtYSpAUFfjuj00ttYrBE4D");function y(e){let{handleClose:s,show:a,planData:t}=e;const l=JSON.parse(localStorage.getItem("family_doc_app")),[n,o]=(0,r.useState)(!1),c=(0,d.I0)(),u=(0,f.s0)(),v=()=>{u(i.m.PATIENT_PLANS)};return(0,j.jsxs)(j.Fragment,{children:[(0,j.jsx)(x.Ix,{}),(0,j.jsx)(h.Z,{handleClose:s,show:a,title:"Checkout",className:"modal-stripe",backdrop:"static",children:(0,j.jsx)(m.Elements,{stripe:b,children:(0,j.jsx)(w,{isLoading:n,setIsLoading:o,newCoachHire:function(e){let s={patientPlanId:0,planId:null===t||void 0===t?void 0:t.planId,userId:null===l||void 0===l?void 0:l.userId,patientStripeCustomerId:null===l||void 0===l?void 0:l.patientStripeCustomerId,stripeToken:e,fee:null===t||void 0===t?void 0:t.amount,planDuration:null===t||void 0===t?void 0:t.duration};c((0,N.Mk)({finalData:s,moveToNext:v}))},planData:t})})})]})}const C=()=>{const e=function(){const e=()=>window.innerWidth<450?"16px":"18px",[s,a]=(0,r.useState)(e);return(0,r.useEffect)((()=>{const s=()=>{a(e())};return window.addEventListener("resize",s),()=>{window.removeEventListener("resize",s)}})),s}();return(0,r.useMemo)((()=>({style:{base:{fontSize:e,color:"#424770",letterSpacing:"0.025em",fontFamily:"Source Code Pro, monospace","::placeholder":{color:"#aab7c4"}},invalid:{color:"#9e2146"}}})),[e])},w=e=>{var s;let{isLoading:a,setIsLoading:r,newCoachHire:t,planData:l}=e;const n=(0,m.useStripe)(),i=(0,m.useElements)(),d=C(),u=null===l||void 0===l||null===(s=l.amount)||void 0===s?void 0:s.toFixed(2);return(0,j.jsxs)("div",{className:"py-2 stripe",children:[(0,j.jsxs)("div",{children:[(0,j.jsx)(c.Z,{children:"Subscription Plan Fee"}),(0,j.jsx)("input",{type:"text",value:"\u20ac".concat(u||"N/A"),disabled:!0,className:"mt-0 w-100"})]}),(0,j.jsxs)("form",{onSubmit:async e=>{if(r(!0),e.preventDefault(),n&&i)try{var s;const e=i.getElement(m.CardNumberElement),r=await n.createToken(e);var a;if(r.error)throw new Error(null===r||void 0===r||null===(a=r.error)||void 0===a?void 0:a.message);const l=null===r||void 0===r||null===(s=r.token)||void 0===s?void 0:s.id;l&&t(l)}catch(l){(0,p.P_)(null===l||void 0===l?void 0:l.message,"error"),r(!1)}},children:[(0,j.jsxs)("div",{children:["Card number",(0,j.jsx)(m.CardNumberElement,{options:d})]}),(0,j.jsxs)("div",{children:["Expiration date",(0,j.jsx)(m.CardExpiryElement,{options:d})]}),(0,j.jsxs)("div",{children:["CVC",(0,j.jsx)(m.CardCvcElement,{options:d})]}),(0,j.jsx)("div",{className:"d-flex justify-content-center mt-3",children:(0,j.jsx)(o.Z,{variant:"primary",className:"w-100 py-2 primary_bg",radius:"0px",type:"submit",disabled:a,children:a?(0,j.jsx)(v.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Confirm"})})]})]})};const P=function(e){let{subscriptionPlansList:s}=e;const[a,t]=(0,r.useState)(),[l,n]=(0,r.useState)(!1);return(0,j.jsxs)("div",{className:"patient__prescription-forms custom-plans",children:[null===s||void 0===s?void 0:s.map(((e,s)=>(0,j.jsxs)("div",{className:"container",children:[(0,j.jsx)("h3",{className:"title mt-2 fw-bold",children:null===e||void 0===e?void 0:e.name}),(0,j.jsxs)("h3",{className:"price",children:["\u20ac",null===e||void 0===e?void 0:e.amount,(0,j.jsxs)("span",{children:[" / ",null===e||void 0===e?void 0:e.duration]})]}),(0,j.jsx)("p",{className:"description",children:null===e||void 0===e?void 0:e.description}),(0,j.jsxs)("p",{className:"m-0",children:[(0,j.jsx)("b",{children:"No. of Appointment(s):"})," ",null===e||void 0===e?void 0:e.numberOfConsultation]}),(0,j.jsxs)("p",{className:"m-0",children:[(0,j.jsx)("b",{children:"No. of Prescription(s):"})," ",null===e||void 0===e?void 0:e.numberOfPrescriptions]}),(0,j.jsx)(o.Z,{className:"subscribe-button",onClick:()=>{n(!0),t(e)},children:"Buy Now"})]},"id-".concat(s)))),(0,j.jsx)(y,{planData:a,handleClose:()=>n(!1),show:l})]})};var g=a(84129);function E(){const{subscriptionPlansList:e,isLoading:s,isError:a,isSuccess:o}=(0,d.v9)((e=>null===e||void 0===e?void 0:e.subscriptionPlans)),c=(0,d.I0)();return(0,r.useEffect)((()=>{c((0,N.Kt)())}),[c]),(0,j.jsxs)(j.Fragment,{children:[(0,j.jsx)("nav",{"aria-label":"breadcrumb",children:(0,j.jsxs)("ol",{className:"breadcrumb",children:[(0,j.jsx)("li",{className:"breadcrumb-item",children:(0,j.jsx)(l.rU,{to:i.m.PATIENT_PLANS,className:"text-decoration-none fs-5 color-99",children:"My Plans"})}),(0,j.jsx)(n.hjJ,{className:"mx-1 mt-2 color-99"}),(0,j.jsx)("li",{className:"breadcrumb-item active fs-5","aria-current":"page",style:{color:"#000071"},children:"Subscription Plans"})]})}),(0,j.jsx)(t.Z,{className:"shadow-sm p-4",children:(0,j.jsx)("div",{children:s?(0,j.jsx)(g.Z,{}):o?(null===e||void 0===e?void 0:e.length)>0?(0,j.jsx)(P,{subscriptionPlansList:e}):(0,j.jsx)("p",{className:"record-message",children:"No Records to Display"}):a?(0,j.jsx)("span",{className:"text-danger fst-italic",children:"Network Error"}):null})})]})}},95070:(e,s,a)=>{a.d(s,{Z:()=>F});var r=a(41418),t=a.n(r),l=a(72791),n=a(10162),i=a(80184);const o=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,n.vE)(r,"card-body"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));o.displayName="CardBody";const c=o,d=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,n.vE)(r,"card-footer"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));d.displayName="CardFooter";const m=d;var u=a(96040);const x=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,as:o="div",...c}=e;const d=(0,n.vE)(a,"card-header"),m=(0,l.useMemo)((()=>({cardHeaderBsPrefix:d})),[d]);return(0,i.jsx)(u.Z.Provider,{value:m,children:(0,i.jsx)(o,{ref:s,...c,className:t()(r,d)})})}));x.displayName="CardHeader";const v=x,p=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,variant:l,as:o="img",...c}=e;const d=(0,n.vE)(a,"card-img");return(0,i.jsx)(o,{ref:s,className:t()(l?"".concat(d,"-").concat(l):d,r),...c})}));p.displayName="CardImg";const f=p,h=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="div",...o}=e;return r=(0,n.vE)(r,"card-img-overlay"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));h.displayName="CardImgOverlay";const N=h,j=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="a",...o}=e;return r=(0,n.vE)(r,"card-link"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));j.displayName="CardLink";const b=j;var y=a(27472);const C=(0,y.Z)("h6"),w=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=C,...o}=e;return r=(0,n.vE)(r,"card-subtitle"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));w.displayName="CardSubtitle";const P=w,g=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l="p",...o}=e;return r=(0,n.vE)(r,"card-text"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));g.displayName="CardText";const E=g,S=(0,y.Z)("h5"),Z=l.forwardRef(((e,s)=>{let{className:a,bsPrefix:r,as:l=S,...o}=e;return r=(0,n.vE)(r,"card-title"),(0,i.jsx)(l,{ref:s,className:t()(a,r),...o})}));Z.displayName="CardTitle";const I=Z,k=l.forwardRef(((e,s)=>{let{bsPrefix:a,className:r,bg:l,text:o,border:d,body:m=!1,children:u,as:x="div",...v}=e;const p=(0,n.vE)(a,"card");return(0,i.jsx)(x,{ref:s,...v,className:t()(r,p,l&&"bg-".concat(l),o&&"text-".concat(o),d&&"border-".concat(d)),children:m?(0,i.jsx)(c,{children:u}):u})}));k.displayName="Card";const F=Object.assign(k,{Img:f,Title:I,Subtitle:P,Body:c,Link:b,Text:E,Header:v,Footer:m,ImgOverlay:N})},96040:(e,s,a)=>{a.d(s,{Z:()=>t});const r=a(72791).createContext(null);r.displayName="CardHeaderContext";const t=r},84934:(e,s,a)=>{a.d(s,{Z:()=>r});const r=a(72791).createContext({})},53392:(e,s,a)=>{a.d(s,{Z:()=>m});var r=a(41418),t=a.n(r),l=a(72791),n=(a(42391),a(2677)),i=a(84934),o=a(10162),c=a(80184);const d=l.forwardRef(((e,s)=>{let{as:a="label",bsPrefix:r,column:d=!1,visuallyHidden:m=!1,className:u,htmlFor:x,...v}=e;const{controlId:p}=(0,l.useContext)(i.Z);r=(0,o.vE)(r,"form-label");let f="col-form-label";"string"===typeof d&&(f="".concat(f," ").concat(f,"-").concat(d));const h=t()(u,r,m&&"visually-hidden",d&&f);return x=x||p,d?(0,c.jsx)(n.Z,{ref:s,as:"label",className:h,htmlFor:x,...v}):(0,c.jsx)(a,{ref:s,className:h,htmlFor:x,...v})}));d.displayName="FormLabel";const m=d}}]);
//# sourceMappingURL=6933.88da07fd.chunk.js.map