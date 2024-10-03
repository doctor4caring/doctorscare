"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[1481],{14045:(e,s,a)=>{a.d(s,{Z:()=>i});var l=a(88135),n=a(80184);function i(e){let{children:s,...a}=e;const{handleClose:i,show:t,title:r,className:c}=a;return(0,n.jsx)("div",{children:(0,n.jsxs)(l.Z,{show:t,onHide:i,className:c,backdrop:"static",children:[(0,n.jsx)(l.Z.Header,{className:"py-3",closeButton:!0,children:(0,n.jsx)(l.Z.Title,{className:"modalTitle",children:(0,n.jsx)("span",{className:"font-weight-600",children:r})})}),(0,n.jsx)(l.Z.Body,{children:s})]})})}},11481:(e,s,a)=>{a.r(s),a.d(s,{default:()=>N});var l=a(72791),n=a(95070),i=a(43360),t=a(8116),r=a(69499),c=a(30203),d=a(57689),o=a(3810),m=a(59434),h=a(65426),x=a(46587),v=a(82962),u=a(14045),f=a(80184);function p(e){let{...s}=e;const{show:a,handleClose:l}=s;return(0,f.jsx)("div",{className:"AddSlot_modal",children:(0,f.jsx)(u.Z,{className:"modal-lg",handleClose:l,show:a,children:(0,f.jsxs)("div",{className:"d-flex justify-content-center flex-column align-items-center text-center p-3",children:[(0,f.jsx)("p",{className:"fw-bold",children:"You have already purchased a plan"}),(0,f.jsx)("div",{className:"d-flex justify-content-center",children:(0,f.jsx)(i.Z,{className:"block primary_bg px-4",variant:"primary",type:"button",onClick:l,children:"Ok"})})]})})})}function N(){const[e,s]=(0,l.useState)(1),a=(0,d.s0)(),u=(0,m.I0)(),[N,j]=(0,l.useState)(!1),{getAllPatientPlanList:b,isLoading:g,isSuccess:y,isError:P}=(0,m.v9)((e=>null===e||void 0===e?void 0:e.subscriptionPlans));console.log("getAllPatientPlanList",b);const w=JSON.parse(localStorage.getItem("family_doc_app")),C=12*e,Z=C-12,k=b&&b.length?b.slice(Z,Math.min(C,b.length)):[];console.log("getAllPatientPlanList",b);const A=e=>s(e);(0,l.useEffect)((()=>{const s={patientId:null===w||void 0===w?void 0:w.userId,IsPagination:!0,PageNo:e,Size:5};u((0,h.bd)(s))}),[u,null===w||void 0===w?void 0:w.userId,e]);const{remainingAptPresData:E}=(0,m.v9)((e=>null===e||void 0===e?void 0:e.doctorSchedule));return(0,l.useEffect)((()=>{const e={patientId:null===w||void 0===w?void 0:w.userId};u((0,v.lr)(e))}),[u,null===w||void 0===w?void 0:w.userId]),(0,f.jsxs)(f.Fragment,{children:[(0,f.jsx)("h5",{children:"My Plans"}),(0,f.jsx)(n.Z,{className:"shadow-sm mt-4 p-3",children:y?(0,f.jsxs)(f.Fragment,{children:[(0,f.jsx)("div",{className:"d-flex justify-content-end",children:(0,f.jsx)(i.Z,{variant:"primary",type:"button",className:"d-flex Admin-Add-btn fw-bold",onClick:()=>{var e,s;null!==E&&void 0!==E&&null!==(e=E.data)&&void 0!==e&&e.appointment&&null!==E&&void 0!==E&&null!==(s=E.data)&&void 0!==s&&s.prescription?j(!0):a(o.m.PATIENT_PURCHASE_PLANS)},children:(null===b||void 0===b?void 0:b.length)>0?"Purchase Another Plan":"Purchase Plan"})}),(0,f.jsx)("div",{children:(null===b||void 0===b?void 0:b.length)>0?(0,f.jsx)("div",{className:"my-plans patient__prescription-forms my-3",children:k.map(((e,s)=>(0,f.jsxs)("div",{className:"container",children:[(0,f.jsx)("h4",{className:"fw-bold m-0",children:null===e||void 0===e?void 0:e.plan}),(0,f.jsxs)("div",{className:"d-flex align-items-end justify-content-center my-4",children:[(0,f.jsxs)("h2",{className:"fw-bold m-0 me-2",children:["$",null===e||void 0===e?void 0:e.amount]}),(0,f.jsx)("span",{className:"day-left-status px-3",children:null===e||void 0===e?void 0:e.remainingPlanDays})]}),(0,f.jsxs)("div",{className:"patient__subscription-plan",children:[(0,f.jsxs)("div",{className:"plans-count",children:[(0,f.jsx)("img",{src:r.Z.APPOINTMENT_ICON,alt:"appointment icon",className:"color-dk-blue mb-2",width:30}),(0,f.jsx)("h6",{className:"m-0",children:"Appointments"}),(0,f.jsx)("h5",{className:"fw-bold m-0",children:null===e||void 0===e?void 0:e.remaingAppointments})]}),(0,f.jsxs)("div",{className:"plans-count",children:[(0,f.jsx)(c.zY5,{className:"color-dk-blue mb-2",size:32}),(0,f.jsx)("h6",{className:"m-0",children:"Prescriptions"}),(0,f.jsx)("h5",{className:"fw-bold m-0",children:null===e||void 0===e?void 0:e.remaingPrescription})]})]}),(0,f.jsx)("div",{className:"ribbon-wrap",children:(0,f.jsx)("div",{className:"ribbon ".concat(null!==e&&void 0!==e&&e.isActive?"active-status":"inactive-status"),children:null!==e&&void 0!==e&&e.isActive?"Active":"InActive"})})]},s)))}):(0,f.jsxs)("div",{className:"d-flex justify-content-center flex-column align-items-center",style:{minHeight:"32rem"},children:[(0,f.jsx)("img",{src:r.Z.PURCHASE_PLANS,alt:"purchase plans line",width:97}),(0,f.jsxs)("p",{className:"text-center",children:["You don't have any purchased Plan Please click on"," ",(0,f.jsx)("span",{className:"fw-bold",children:"Purchase Plan"})]})]})}),b.length>0&&(0,f.jsxs)(t.Z,{className:"d-flex justify-content-between align-items-center px-3 patient__prescription-pagination",children:[(0,f.jsx)(t.Z,{children:(I=Z+1,_=C,R=b.length,(0,f.jsxs)("span",{children:[I," to ",_," out of ",R," entries"]}))}),(0,f.jsxs)("div",{className:"d-flex justify-content-between pagination__page-Number",children:[(0,f.jsx)(t.Z.Prev,{onClick:()=>A(e-1),disabled:1===e}),Array.from({length:Math.ceil(b.length/12)}).map(((s,a)=>(0,f.jsx)(t.Z.Item,{active:e===a+1,onClick:()=>A(a+1),children:a+1},a+1))),(0,f.jsx)(t.Z.Next,{onClick:()=>A(e+1),disabled:e===Math.ceil(b.length/12)})]})]})]}):g?(0,f.jsx)(x.Z,{}):P?(0,f.jsx)("p",{className:"text-center mt-3",children:"Network Error..."}):null}),(0,f.jsx)(p,{handleClose:()=>j(!1),show:N})]});var I,_,R}},95070:(e,s,a)=>{a.d(s,{Z:()=>_});var l=a(81694),n=a.n(l),i=a(72791),t=a(10162),r=a(80184);const c=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:i="div",...c}=e;return l=(0,t.vE)(l,"card-body"),(0,r.jsx)(i,{ref:s,className:n()(a,l),...c})}));c.displayName="CardBody";const d=c,o=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:i="div",...c}=e;return l=(0,t.vE)(l,"card-footer"),(0,r.jsx)(i,{ref:s,className:n()(a,l),...c})}));o.displayName="CardFooter";const m=o;var h=a(96040);const x=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:l,as:c="div",...d}=e;const o=(0,t.vE)(a,"card-header"),m=(0,i.useMemo)((()=>({cardHeaderBsPrefix:o})),[o]);return(0,r.jsx)(h.Z.Provider,{value:m,children:(0,r.jsx)(c,{ref:s,...d,className:n()(l,o)})})}));x.displayName="CardHeader";const v=x,u=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:l,variant:i,as:c="img",...d}=e;const o=(0,t.vE)(a,"card-img");return(0,r.jsx)(c,{ref:s,className:n()(i?"".concat(o,"-").concat(i):o,l),...d})}));u.displayName="CardImg";const f=u,p=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:i="div",...c}=e;return l=(0,t.vE)(l,"card-img-overlay"),(0,r.jsx)(i,{ref:s,className:n()(a,l),...c})}));p.displayName="CardImgOverlay";const N=p,j=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:i="a",...c}=e;return l=(0,t.vE)(l,"card-link"),(0,r.jsx)(i,{ref:s,className:n()(a,l),...c})}));j.displayName="CardLink";const b=j;var g=a(27472);const y=(0,g.Z)("h6"),P=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:i=y,...c}=e;return l=(0,t.vE)(l,"card-subtitle"),(0,r.jsx)(i,{ref:s,className:n()(a,l),...c})}));P.displayName="CardSubtitle";const w=P,C=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:i="p",...c}=e;return l=(0,t.vE)(l,"card-text"),(0,r.jsx)(i,{ref:s,className:n()(a,l),...c})}));C.displayName="CardText";const Z=C,k=(0,g.Z)("h5"),A=i.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:i=k,...c}=e;return l=(0,t.vE)(l,"card-title"),(0,r.jsx)(i,{ref:s,className:n()(a,l),...c})}));A.displayName="CardTitle";const E=A,I=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:l,bg:i,text:c,border:o,body:m=!1,children:h,as:x="div",...v}=e;const u=(0,t.vE)(a,"card");return(0,r.jsx)(x,{ref:s,...v,className:n()(l,u,i&&"bg-".concat(i),c&&"text-".concat(c),o&&"border-".concat(o)),children:m?(0,r.jsx)(d,{children:h}):h})}));I.displayName="Card";const _=Object.assign(I,{Img:f,Title:E,Subtitle:w,Body:d,Link:b,Text:Z,Header:v,Footer:m,ImgOverlay:N})},96040:(e,s,a)=>{a.d(s,{Z:()=>n});const l=a(72791).createContext(null);l.displayName="CardHeaderContext";const n=l},8116:(e,s,a)=>{a.d(s,{Z:()=>N});var l=a(81694),n=a.n(l),i=a(72791),t=a(10162),r=a(16445),c=a(80184);const d=i.forwardRef(((e,s)=>{let{active:a=!1,disabled:l=!1,className:i,style:t,activeLabel:d="(current)",children:o,linkStyle:m,linkClassName:h,...x}=e;const v=a||l?"span":r.Z;return(0,c.jsx)("li",{ref:s,style:t,className:n()(i,"page-item",{active:a,disabled:l}),children:(0,c.jsxs)(v,{className:n()("page-link",h),style:m,...x,children:[o,a&&d&&(0,c.jsx)("span",{className:"visually-hidden",children:d})]})})}));d.displayName="PageItem";const o=d;function m(e,s){let a=arguments.length>2&&void 0!==arguments[2]?arguments[2]:e;const l=i.forwardRef(((e,l)=>{let{children:n,...i}=e;return(0,c.jsxs)(d,{...i,ref:l,children:[(0,c.jsx)("span",{"aria-hidden":"true",children:n||s}),(0,c.jsx)("span",{className:"visually-hidden",children:a})]})}));return l.displayName=e,l}const h=m("First","\xab"),x=m("Prev","\u2039","Previous"),v=m("Ellipsis","\u2026","More"),u=m("Next","\u203a"),f=m("Last","\xbb"),p=i.forwardRef(((e,s)=>{let{bsPrefix:a,className:l,size:i,...r}=e;const d=(0,t.vE)(a,"pagination");return(0,c.jsx)("ul",{ref:s,...r,className:n()(l,d,i&&"".concat(d,"-").concat(i))})}));p.displayName="Pagination";const N=Object.assign(p,{First:h,Prev:x,Ellipsis:v,Item:o,Next:u,Last:f})}}]);
//# sourceMappingURL=1481.1c4edb0b.chunk.js.map