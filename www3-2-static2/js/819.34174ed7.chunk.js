"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[819],{39430:(e,a,s)=>{s.r(a),s.d(a,{default:()=>C});var l=s(72791),t=s(89743),n=s(2677),i=s(95070),c=s(4053),r=s(59513),d=s.n(r),o=(s(68639),s(78820)),m=s(72426),x=s.n(m),p=s(24278),h=s(59434),u=s(80184);function j(){const[e,a]=(0,l.useState)(new Date),[s,t]=(0,l.useState)(null),n=(0,h.I0)(),{allAppointment:r}=(0,h.v9)((e=>null===e||void 0===e?void 0:e.appointment));(0,l.useEffect)((()=>{const a={isDashbaordAppointment:!0,startdate:e?x()(e).format("YYYY-MM-DD"):x()(new Date).format("YYYY-MM-DD"),endDate:e?x()(e).format("YYYY-MM-DD"):x()(new Date).format("YYYY-MM-DD"),statusId:202};n((0,p.Qe)(a))}),[n,e,s]);const[m,j]=(0,l.useState)(0);return(0,u.jsx)(u.Fragment,{children:(0,u.jsxs)(i.Z,{className:"py-4 m-0",children:[(0,u.jsxs)("span",{className:"d-flex align-items-center px-4 pb-0 ",children:[(0,u.jsx)("img",{src:c.Z.APPOINTMENT_ICON,alt:"new patient icon",style:{width:"20px"},className:"me-2"}),(0,u.jsx)(i.Z.Title,{className:"m-0",children:"Calendar"})]}),(0,u.jsx)(i.Z.Body,{className:"px-0",children:(0,u.jsx)("span",{className:"patient-calendar",children:(0,u.jsx)(d(),{selected:e,onChange:e=>a(e),startDate:e,inline:!0})})}),(0,u.jsx)("div",{className:(null===r||void 0===r?void 0:r.length)>0?"patient-custom-scrollbar-admin":"custom-apt-height-admin",children:(null===r||void 0===r?void 0:r.length)>0?null===r||void 0===r?void 0:r.map(((e,a)=>(0,u.jsxs)(i.Z.Body,{className:"mx-4 mb-3 calendar-card",children:[(0,u.jsx)(i.Z.Title,{style:{fontSize:"24px"}}),(0,u.jsxs)("div",{className:"d-flex align-items-center",children:[(0,u.jsxs)("span",{className:"me-3 apt-inner-card p-2 d-flex align-items-center flex-column",children:[(0,u.jsx)("p",{style:{fontSize:"26px",fontWeight:600},className:"mb-0",children:x()(null===e||void 0===e?void 0:e.appointmentDate).format("MMM DD")}),(0,u.jsxs)("p",{className:"m-0 table-normal-text",children:[(0,u.jsx)(o.Gtc,{className:"me-2",style:{color:"#999999"}}),null===e||void 0===e?void 0:e.appointmentStartTime]})]}),(0,u.jsx)("span",{style:{lineHeight:"1.4"},children:(0,u.jsx)("p",{className:"m-0",style:{fontSize:"18px"},children:null===e||void 0===e?void 0:e.doctorName})})]}),(0,u.jsxs)("span",{children:[(0,u.jsx)("p",{className:"color-99 mt-3 mb-2",children:"Reason:"}),(0,u.jsx)("p",{className:"mb-0",style:{fontSize:"16px",fontWeight:500},children:null===e||void 0===e?void 0:e.reasonForAppoinment})]})]}))):(0,u.jsxs)("div",{className:"px-3",children:[(0,u.jsx)("p",{style:{fontSize:"20px",fontWeight:500},className:"mb-0",children:"Upcoming Appointment"}),(0,u.jsxs)("div",{className:"py-2 d-flex justify-content-center align-items-center flex-column",children:[(0,u.jsx)("img",{src:c.Z.UPCOMING_APPOINTMENT_ICON,alt:"upcoming appointment"}),(0,u.jsx)("p",{className:"mb-0 mt-2 color-99 text-center",style:{fontSize:"20px",fontWeight:400,width:"54%"},children:"No appointment scheduled"})]})]})})]})})}var g=s(45736),N=s(36638),f=s(1444),b=s(7692),v=s(2002),Z=s(36161),y=s(17425),F=s(39698);function S(){const[e,a]=(0,l.useState)(null),[s,c]=(0,l.useState)(),r=(0,h.I0)(),{getAllApt:d}=(0,h.v9)((e=>null===e||void 0===e?void 0:e.adminDashboard));(0,l.useEffect)((()=>{const a={pageNo:0,size:0,isPagination:!1,search:s||null,statusId:"205"===e?205:"204"===e?204:"206"===e?206:"203"===e?203:"201"===e?201:"202"===e?202:null};r((0,F.qQ)(a))}),[r,s,e]);const o=[{dataField:"id",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"doctorName",text:"Doctor Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"patientName",text:"Patient Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"appointmentDate",text:"Date",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const a=new Date(e),s=a.getDate().toString().padStart(2,"0"),l=(a.getMonth()+1).toString().padStart(2,"0"),t=a.getFullYear();return"".concat(l,"/").concat(s,"/").concat(t)}},{dataField:"appointmentTime",text:"Time",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"status",text:"Status",formatter:(e,a)=>{return 204===(s=null===a||void 0===a?void 0:a.statusId)?(0,u.jsx)(g.Z,{pill:!0,bg:"info",className:"upcoming-badge",children:"Upcoming"}):201===s?(0,u.jsx)(g.Z,{pill:!0,bg:"primary",className:"pending-badge",children:"Pending"}):205===s?(0,u.jsx)(g.Z,{pill:!0,bg:"danger",className:"missed-badge",children:"Missed"}):206===s?(0,u.jsx)(g.Z,{pill:!0,bg:"light",className:"completed-badge",children:"Completed"}):203===s?(0,u.jsx)(g.Z,{pill:!0,bg:"warning",className:"cancelled-badge",children:"Cancelled"}):(0,u.jsx)(g.Z,{children:"Booked"});var s},headerStyle:{backgroundColor:"#F1F1F1"}}],m={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,a,s)=>(0,u.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[e," to ",a," out of ",s," entries"]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,u.jsx)(u.Fragment,{children:(0,u.jsx)(i.Z,{className:"mb-0 ",children:(0,u.jsxs)(i.Z.Body,{className:"p-0",children:[(0,u.jsxs)(t.Z,{className:"px-4 pt-3",children:[(0,u.jsx)(n.Z,{md:4,className:"d-flex align-items-center",children:(0,u.jsx)(i.Z.Title,{className:"mb-0",children:"Appointments"})}),(0,u.jsxs)(n.Z,{md:8,className:"d-flex flex-wrap align-self-center justify-content-end",children:[(0,u.jsxs)("span",{className:"d-flex justify-content-between align-self-center",children:[(0,u.jsx)(N.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&c(e.target.value)},onChange:e=>{"Enter"===e.key&&c(e.target.value)},type:"text",placeholder:"Search",className:"search-field-spacing mb-2","aria-label":"Search"}),(0,u.jsx)(b.Goc,{size:22,className:"searchbar-icon"})]}),(0,u.jsxs)(f.Z,{className:"apt-filter-dropdown mb-2",children:[(0,u.jsx)(f.Z.Toggle,{variant:"secondary",id:"checkbox-dropdown",className:"custom-outline-filter py-2",children:(0,u.jsx)(y.i3E,{size:28,className:"color-99"})}),(0,u.jsx)(f.Z.Menu,{children:(0,u.jsx)(N.Z,{children:[{label:"Missed",value:205},{label:"Upcoming",value:204},{label:"Completed",value:206},{label:"Cancelled",value:203},{label:"Pending",value:201},{label:"Booked",value:202}].map((s=>(0,u.jsx)(N.Z.Check,{type:"checkbox",label:s.label,value:s.value,checked:null!==e&&e.includes(s.value),onChange:s=>a(e===s.target.value?null:s.target.value)},s.value)))})})]})]})]}),(0,u.jsx)("span",{className:"patient-datatable apt-badge",children:(0,u.jsx)(v.Z,{columns:o,data:d||[],keyField:"id",id:"bar",pagination:(0,Z.ZP)(m),bordered:!1,wrapperClasses:"table-responsive"})})]})})})}function C(){const e=(0,h.I0)(),{adminDashCount:a}=(0,h.v9)((e=>null===e||void 0===e?void 0:e.adminDashboard));return(0,l.useEffect)((()=>{e((0,F.uc)())}),[e]),(0,u.jsxs)(u.Fragment,{children:[(0,u.jsxs)(t.Z,{className:"main-row patient-dashbaord",children:[(0,u.jsx)(n.Z,{sm:4,xs:12,className:"xs-margin-bottom",children:(0,u.jsx)(i.Z,{className:"h-100",children:(0,u.jsxs)(i.Z.Body,{className:"d-flex justify-content-between align-items-center p-4 display-column-reverse",children:[(0,u.jsxs)("span",{children:[(0,u.jsx)(i.Z.Title,{children:"Total Patients"}),(0,u.jsx)("h3",{className:"mb-0",children:null===a||void 0===a?void 0:a.totalPatient})]}),(0,u.jsx)("img",{src:c.Z.NEW_PATIENT_ICON,alt:"total patients"})]})})}),(0,u.jsx)(n.Z,{sm:4,xs:12,className:"xs-margin-bottom",children:(0,u.jsx)(i.Z,{className:"h-100",children:(0,u.jsxs)(i.Z.Body,{className:"d-flex justify-content-between align-items-center p-4 display-column-reverse",children:[(0,u.jsxs)("span",{children:[(0,u.jsx)(i.Z.Title,{children:"Total Doctors"}),(0,u.jsx)("h3",{className:"mb-0",children:null===a||void 0===a?void 0:a.totalDoctor})]}),(0,u.jsx)("img",{src:c.Z.TOTAL_DOCTORS_ICON,alt:"total doctors"})]})})}),(0,u.jsx)(n.Z,{sm:4,xs:12,className:"xs-margin-bottom",children:(0,u.jsx)(i.Z,{className:"h-100",children:(0,u.jsxs)(i.Z.Body,{className:"d-flex justify-content-between align-items-center p-4 display-column-reverse",children:[(0,u.jsxs)("span",{children:[(0,u.jsx)(i.Z.Title,{children:"Total Staff"}),(0,u.jsx)("h3",{className:"mb-0",children:null===a||void 0===a?void 0:a.totalStaff})]}),(0,u.jsx)("img",{src:c.Z.TOTAL_STAFF_ICON,alt:"total staff"})]})})})]}),(0,u.jsxs)(t.Z,{className:"my-3",children:[(0,u.jsx)(n.Z,{xl:8,xs:12,children:(0,u.jsx)(t.Z,{children:(0,u.jsx)(n.Z,{xs:12,className:"mb-3",children:(0,u.jsx)(S,{})})})}),(0,u.jsx)(n.Z,{xl:4,xs:12,children:(0,u.jsx)(t.Z,{children:(0,u.jsx)(n.Z,{xs:12,children:(0,u.jsx)(j,{})})})})]})]})}},45736:(e,a,s)=>{s.d(a,{Z:()=>d});var l=s(81694),t=s.n(l),n=s(72791),i=s(10162),c=s(80184);const r=n.forwardRef(((e,a)=>{let{bsPrefix:s,bg:l="primary",pill:n=!1,text:r,className:d,as:o="span",...m}=e;const x=(0,i.vE)(s,"badge");return(0,c.jsx)(o,{ref:a,...m,className:t()(d,x,n&&"rounded-pill",r&&"text-".concat(r),l&&"bg-".concat(l))})}));r.displayName="Badge";const d=r},11701:(e,a,s)=>{s.d(a,{Ed:()=>n,UI:()=>t,XW:()=>i});var l=s(72791);function t(e,a){let s=0;return l.Children.map(e,(e=>l.isValidElement(e)?a(e,s++):e))}function n(e,a){let s=0;l.Children.forEach(e,(e=>{l.isValidElement(e)&&a(e,s++)}))}function i(e,a){return l.Children.toArray(e).some((e=>l.isValidElement(e)&&e.type===a))}}}]);
//# sourceMappingURL=819.34174ed7.chunk.js.map