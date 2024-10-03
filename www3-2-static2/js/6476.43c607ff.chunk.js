"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6476],{96476:(e,a,s)=>{s.r(a),s.d(a,{default:()=>C});var l=s(72791),n=s(89743),i=s(2677),t=s(81694),r=s.n(t),c=s(10162),d=s(11701),m=s(80184);const o=1e3;function x(e,a,s){const l=(e-a)/(s-a)*100;return Math.round(l*o)/o}function f(e,a){let{min:s,now:l,max:n,label:i,visuallyHidden:t,striped:c,animated:d,className:o,style:f,variant:h,bsPrefix:u,...p}=e;return(0,m.jsx)("div",{ref:a,...p,role:"progressbar",className:r()(o,"".concat(u,"-bar"),{["bg-".concat(h)]:h,["".concat(u,"-bar-animated")]:d,["".concat(u,"-bar-striped")]:d||c}),style:{width:"".concat(x(l,s,n),"%"),...f},"aria-valuenow":l,"aria-valuemin":s,"aria-valuemax":n,children:t?(0,m.jsx)("span",{className:"visually-hidden",children:i}):i})}const h=l.forwardRef(((e,a)=>{let{isChild:s=!1,...n}=e;const i={min:0,max:100,animated:!1,visuallyHidden:!1,striped:!1,...n};if(i.bsPrefix=(0,c.vE)(i.bsPrefix,"progress"),s)return f(i,a);const{min:t,now:o,max:x,label:h,visuallyHidden:u,striped:p,animated:b,bsPrefix:j,variant:N,className:v,children:y,...g}=i;return(0,m.jsx)("div",{ref:a,...g,className:r()(v,j),children:y?(0,d.UI)(y,(e=>(0,l.cloneElement)(e,{isChild:!0}))):f({min:t,now:o,max:x,label:h,visuallyHidden:u,striped:p,animated:b,bsPrefix:j,variant:N},a)})}));h.displayName="ProgressBar";const u=h,p=()=>(0,m.jsxs)(n.Z,{className:"profileHeader px-5 d-flex align-items-center justify-content-between",children:[(0,m.jsx)(i.Z,{xl:3,className:"d-flex",children:(0,m.jsx)("h2",{className:"fw-bold fs-3 mb-0",children:"Complete Profile"})}),(0,m.jsxs)(i.Z,{xl:4,className:"d-flex align-items-center justify-content-between",children:[(0,m.jsx)("h6",{className:"fw-semibold text-nowrap mb-0",children:"Profile Completed"}),(0,m.jsx)("div",{className:"w-75 mx-3",children:(0,m.jsx)(u,{now:20})}),(0,m.jsx)("h6",{className:"fw-semibold mb-0",children:"20%"})]})]});var b=s(11087),j=s(56355),N=s(3810),v=s(4053);const y=[{label:"General Information",link:N.m.PERSONAL_INFORMATION},{label:"Medical History",link:N.m.MEDICAL_HISTORY},{label:"Pharmacy",link:N.m.PHARMACY}],g=e=>{let{activeStep:a}=e;const[s,n]=(0,l.useState)(!1),[i,t]=(0,l.useState)([]);return(0,m.jsxs)(m.Fragment,{children:[(0,m.jsx)("button",{className:"sidebar-toggle",onClick:()=>{n(!s)},children:(0,m.jsx)(j.Fm7,{})}),(0,m.jsx)("div",{className:"profileSidebar ".concat(s?"visible":""),children:(0,m.jsxs)("aside",{className:"d-flex flex-column justify-content-center align-items-center",children:[(0,m.jsx)(b.rU,{to:N.m.PATIENT_DASHBOARD,className:"logo mr-0 header-logo-image text-decoration-none mt-5",children:(0,m.jsx)("img",{alt:"sidebar logo",src:v.Z.SIDEBAR_LOGO})}),(0,m.jsx)("ul",{className:"list-unstyled py-3 mt-5 d-flex flex-column justify-content-center align-items-start",children:y.map(((e,s)=>(0,m.jsxs)("li",{className:"mb-4",children:[(0,m.jsxs)(b.rU,{to:e.link,className:s===a?"active":i.includes(s)?"completed":"",onClick:()=>(e=>{i.includes(e)||t([...i,e])})(s),children:[(0,m.jsx)("span",{className:"p-3 spanBorder rounded-circle me-2",children:"0".concat(s+1)}),e.label]}),s!==y.length-1&&(0,m.jsx)("span",{className:"d-flex justify-content-start ps-4 mt-4",children:(0,m.jsx)("img",{alt:"vertical line",src:v.Z.VERTICAL_LINE})})]},s)))})]})})]})};var w=s(57689);const C=function(e){let{children:a}=e,s=0;switch((0,w.TH)().pathname){case N.m.MEDICAL_HISTORY:s=1;break;case N.m.PHARMACY:s=2;break;default:s=0}return(0,m.jsxs)(m.Fragment,{children:[(0,m.jsx)(p,{}),(0,m.jsxs)("main",{children:[(0,m.jsx)(g,{activeStep:s}),(0,m.jsx)("section",{className:"profile_wrapper px-3 px-md-4 px-lg-0",children:a})]})]})}},11701:(e,a,s)=>{s.d(a,{Ed:()=>i,UI:()=>n,XW:()=>t});var l=s(72791);function n(e,a){let s=0;return l.Children.map(e,(e=>l.isValidElement(e)?a(e,s++):e))}function i(e,a){let s=0;l.Children.forEach(e,(e=>{l.isValidElement(e)&&a(e,s++)}))}function t(e,a){return l.Children.toArray(e).some((e=>l.isValidElement(e)&&e.type===a))}}}]);
//# sourceMappingURL=6476.43c607ff.chunk.js.map