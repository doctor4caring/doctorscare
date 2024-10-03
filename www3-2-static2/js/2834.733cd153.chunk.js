"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[2834],{52218:(e,t,a)=>{a.r(t),a.d(t,{default:()=>S});var l=a(72791),n=a(89743),r=a(2677),s=a(95070),o=a(36638),d=a(7692),i=a(78820),c=a(11087),m=a(2002),p=a(36161),h=a(59513),u=a.n(h),x=a(39126),g=(a(68639),a(59434)),j=a(24278),f=a(46587),F=a(3810),b=a(72426),v=a.n(b),y=a(80184);function N(){const[e,t]=(0,l.useState)(null),[a,h]=(0,l.useState)(null),b=(0,g.I0)(),{allAppointedPatient:N}=(0,g.v9)((e=>null===e||void 0===e?void 0:e.appointment)),{user:S}=(0,g.v9)((e=>e.auth)),{isLoading:C}=(0,g.v9)((e=>e.userRole)),[k,w]=(0,l.useState)();(0,l.useEffect)((()=>{const t={doctorId:null===S||void 0===S?void 0:S.userId,search:k||null,dob:e?v()(e).format("YYYY-MM-DD"):null,gender:a?+a:null};b((0,j.Jl)(t))}),[b,null===S||void 0===S?void 0:S.userId,k,e,a]);const D=[{dataField:"patientId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"patientName",text:"Patient Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,t)=>(0,y.jsxs)("div",{className:"d-flex align-items-center",children:[(0,y.jsx)("img",{src:null!==t&&void 0!==t&&t.imageUrl?null===t||void 0===t?void 0:t.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===t||void 0===t?void 0:t.patientName),"&background=6045eb&color=fff"),alt:"apt patient",className:"me-2 dt-round-img"}),(0,y.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,y.jsx)("p",{className:"m-0 table-bold-text",children:null===t||void 0===t?void 0:t.patientName}),(0,y.jsx)("p",{className:"m-0 table-normal-text",children:null===t||void 0===t?void 0:t.email}),(0,y.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===t||void 0===t?void 0:t.phoneNumber})]})]})},{dataField:"currentAddress",text:"Location",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"createdDate",text:"Created Date",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const t=new Date(e),a=t.getDate().toString().padStart(2,"0"),l=(t.getMonth()+1).toString().padStart(2,"0"),n=t.getFullYear();return"".concat(l,"/").concat(a,"/").concat(n)}},{dataField:"gender",text:"Gender",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"dob",text:"DOB",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const t=new Date(e),a=t.getDate().toString().padStart(2,"0"),l=(t.getMonth()+1).toString().padStart(2,"0"),n=t.getFullYear();return"".concat(l,"/").concat(a,"/").concat(n)}},{dataField:"action",text:"Action",sort:!1,formatter:(e,t)=>(0,y.jsxs)(c.rU,{to:F.m.PATIENTS_DETAILS.replace(":patientId",null===t||void 0===t?void 0:t.patientId),className:"table-action",children:[(0,y.jsx)(i.w8I,{})," View"]}),headerStyle:{backgroundColor:"#F1F1F1"}}],I={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,t,a)=>(0,y.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,y.jsxs)("b",{children:[" ",e," "]})," to ",(0,y.jsx)("b",{children:t})," out of ",(0,y.jsxs)("b",{children:[a," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"6",value:6}]};return(0,y.jsx)(y.Fragment,{children:(0,y.jsx)(s.Z,{className:"shadow-sm patient-card patient-profile-wrapper custom-loading-h",children:(0,y.jsxs)(y.Fragment,{children:[(0,y.jsxs)(n.Z,{className:"px-4 pt-3 d-flex",children:[(0,y.jsx)(r.Z,{md:3,children:(0,y.jsxs)("span",{className:"d-flex",children:[(0,y.jsx)(o.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&w(e.target.value)},onChange:e=>{"Enter"===e.key&&w(e.target.value)},type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing","aria-label":"Search"}),(0,y.jsx)(d.Goc,{size:22,className:"searchbar-icon"})]})}),(0,y.jsxs)(r.Z,{md:9,className:"d-flex flex-wrap align-self-center justify-content-end pe-0",children:[(0,y.jsxs)("div",{className:"d-flex mb-2 me-2",children:[(0,y.jsx)(u(),{selected:e,onChange:e=>t(e),dateFormat:"dd MMM yyyy",placeholderText:"D.O.B",className:"custom-field-picker patient-profile-dob-w px-3"}),(0,y.jsx)(x.zlR,{className:"custom-date-icon",size:18,style:{top:"16px"}})]}),(0,y.jsx)("div",{children:(0,y.jsxs)("select",{onChange:e=>h(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,y.jsx)("option",{selected:!0,children:"Gender"}),(0,y.jsx)("option",{value:101,children:"Male"}),(0,y.jsx)("option",{value:102,children:"Female"}),(0,y.jsx)("option",{value:103,children:"Other"})]})})]})]}),C?(0,y.jsx)(f.Z,{}):(0,y.jsx)("span",{className:"doctor-datatable",children:(0,y.jsx)(m.Z,{columns:D,data:N||[],keyField:"patientId",id:"bar",pagination:(0,p.ZP)(I),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"}})})]})})})}function S(){return(0,y.jsxs)(y.Fragment,{children:[(0,y.jsx)("h5",{children:"My Patients"}),(0,y.jsx)(n.Z,{className:"my-3",children:(0,y.jsx)(r.Z,{xs:12,children:(0,y.jsx)(N,{})})})]})}},11701:(e,t,a)=>{a.d(t,{Ed:()=>r,UI:()=>n,XW:()=>s});var l=a(72791);function n(e,t){let a=0;return l.Children.map(e,(e=>l.isValidElement(e)?t(e,a++):e))}function r(e,t){let a=0;l.Children.forEach(e,(e=>{l.isValidElement(e)&&t(e,a++)}))}function s(e,t){return l.Children.toArray(e).some((e=>l.isValidElement(e)&&e.type===t))}}}]);
//# sourceMappingURL=2834.733cd153.chunk.js.map