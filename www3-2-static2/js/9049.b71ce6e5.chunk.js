"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[9049],{52802:(e,l,a)=>{a.d(l,{Z:()=>t});var s=a(59434),i=a(80184);const t=function(e){var l,a;const{prescriptionData:t}=e,{getUserData:n}=(0,s.v9)((e=>e.userRole));return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsxs)("div",{className:"text-center",children:[(0,i.jsx)("h1",{children:"FamilyDoc247"}),(0,i.jsx)("h6",{children:"General Practitioner (GP) / Family Physician"}),(0,i.jsx)("h6",{children:"Fitzwilliam Hall, Fitzwilliam Place, Dublin 2"}),(0,i.jsx)("h6",{children:"Tel: +353 1 906 9327"}),(0,i.jsx)("h6",{children:"Email : familydoc.gp@healthmail.ie"})]}),(0,i.jsx)("div",{className:"pdf-table",children:(null===t||void 0===t||null===(l=t.medicineList)||void 0===l?void 0:l.length)>0?(0,i.jsx)(i.Fragment,{children:(0,i.jsxs)("div",{className:"my-5",children:[(0,i.jsxs)("table",{children:[(0,i.jsx)("thead",{children:(0,i.jsxs)("tr",{children:[(0,i.jsx)("th",{children:"Medicine"}),(0,i.jsx)("th",{children:"Formulation"}),(0,i.jsx)("th",{children:"Dose"}),(0,i.jsx)("th",{children:"Frequency"}),(0,i.jsx)("th",{children:"Duration"})]})}),(0,i.jsx)("tbody",{children:null===t||void 0===t||null===(a=t.medicineList)||void 0===a?void 0:a.map(((e,l)=>(0,i.jsxs)("tr",{children:[(0,i.jsx)("td",{children:e.medicineName}),(0,i.jsx)("td",{children:e.formulation}),(0,i.jsx)("td",{children:e.dose}),(0,i.jsx)("td",{children:e.doseFrequency}),(0,i.jsx)("td",{children:e.quantity})]},l)))})]}),(0,i.jsxs)("div",{className:"mt-4 mb-5",children:[(0,i.jsx)("h5",{children:"Notes:"}),(0,i.jsx)("ul",{children:null===t||void 0===t?void 0:t.medicineList.map(((e,l)=>(0,i.jsx)("li",{children:e.note?e.note:"N/A"},l)))})]})]})}):(0,i.jsx)("p",{children:"No Record Found"})}),(0,i.jsxs)("div",{className:"d-flex",children:[(0,i.jsxs)("div",{className:"me-5",children:[(0,i.jsxs)("p",{children:["MCRN"," ",null!==t&&void 0!==t&&t.mcrn?null===t||void 0===t?void 0:t.mcrn:null!==n&&void 0!==n&&n.mcrn?null===n||void 0===n?void 0:n.mcrn:"N/A"]}),(0,i.jsxs)("p",{className:"mb-0",children:["Dr"," ",null!==t&&void 0!==t&&t.doctorName?null===t||void 0===t?void 0:t.doctorName:null!==n&&void 0!==n&&n.name?null===n||void 0===n?void 0:n.name:"N/A"]})]}),(0,i.jsx)("span",{style:{display:"inline-block",width:"100px",height:"50px"},children:(0,i.jsx)("img",{src:null===n||void 0===n?void 0:n.doctorSignature,alt:"signature",width:"140px",height:"100px"})})]})]})}},35205:(e,l,a)=>{a.d(l,{Z:()=>m});a(72791);var s=a(88135),i=a(43360),t=a(36638),n=a(74427),r=a(2002),o=a(36161),d=a(63524),c=a(80184);const m=function(e){const{show:l,handleClose:a,viewPresctionData:m}=e,h={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,a)=>{var s;return(null===m||void 0===m||null===(s=m.medicineList)||void 0===s?void 0:s.length)>0&&(0,c.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,c.jsxs)("b",{children:[" ",e," "]})," to ",(0,c.jsx)("b",{children:l})," out of ",(0,c.jsxs)("b",{children:[a," entries"]})]})},disablePageTitle:!0,sizePerPageList:[{text:"6",value:4}]};return(0,c.jsx)("div",{children:(0,c.jsxs)(s.Z,{show:l,onHide:a,centered:!0,size:"xl",className:"Modal-MainClass",children:[(0,c.jsxs)(s.Z.Header,{className:"p-4",children:[(0,c.jsxs)("span",{children:[(0,c.jsx)("img",{src:n,alt:"",style:{height:"100px"}}),(0,c.jsx)("p",{className:"mt-2 mb-0",children:" info@familydoc.com | www.familydoc.com"})]}),(0,c.jsxs)("span",{className:"text-end color-99",children:[(0,c.jsx)("h2",{className:"font-weight-600 mb-0",style:{color:"#1A1A1A"},children:null===m||void 0===m?void 0:m.doctorName}),(0,c.jsx)("h4",{className:"mb-0",children:null===m||void 0===m?void 0:m.doctorId})]})]}),(0,c.jsxs)(s.Z.Body,{className:"px-4",children:[(0,c.jsxs)("div",{className:"w-100 d-flex justify-content-between align-items-center",children:[(0,c.jsxs)("p",{style:{color:"#999999",fontSize:"17px",letterSpacing:"0.5"},children:["Prescription ID:",(0,c.jsx)("span",{style:{color:"#1A1A1A",fontSize:"18px"},className:"fw-bold ms-2",children:null===m||void 0===m?void 0:m.prescriptionId})]}),(0,c.jsxs)("p",{style:{color:"#999999"},className:"Prescription_SpecificResponsive",children:["Name:",(0,c.jsxs)("span",{style:{color:"#1A1A1A",fontSize:"18px"},className:"fw-bold ms-2",children:[null===m||void 0===m?void 0:m.patientName," /"," ",null===m||void 0===m?void 0:m.patientGender," /",null===m||void 0===m?void 0:m.prescribedDate.split("T")[0]]})]})]}),(0,c.jsx)("div",{className:"d-flex justify-content-end mb-2",children:(0,c.jsxs)(i.Z,{className:"border-0 px-3 py-2 rounded-2",style:{background:"#F0F0F0",color:"#1A1A1A"},onClick:()=>{e.onDownload(m)},children:[(0,c.jsx)(d.bAs,{size:20})," Download PDF"]})}),(0,c.jsx)("span",{className:"doctor-datatable ",children:(0,c.jsx)(r.Z,{columns:[{dataField:"medicineId",text:"Sr",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"medicineName",text:"Medicines",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"formulation",text:"Formulation",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"dose",text:"Dose",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"doseFrequency",text:"Frequency",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"quantity",text:"Quantity",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"route",text:"Route",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"}],data:null!==m&&void 0!==m&&m.medicineList?null===m||void 0===m?void 0:m.medicineList:[],keyField:"id",id:"bar",pagination:(0,o.ZP)(h),bordered:!1,wrapperClasses:"table-responsive"})}),(0,c.jsxs)(t.Z.Group,{style:{fontSize:"18px",fontWeight:500},controlId:"exampleForm.ControlTextarea1",children:[(0,c.jsx)(t.Z.Label,{className:"mb-0",children:"Recommended Actions"}),(0,c.jsx)(t.Z.Control,{as:"textarea",rows:2,placeholder:"Tell about some recommended actions",className:"pt-2 mb-2",readOnly:!0,defaultValue:null!==m&&void 0!==m&&m.recommendedActions?null===m||void 0===m?void 0:m.recommendedActions:"N/A"})]})]})]})})}},9049:(e,l,a)=>{a.r(l),a.d(l,{default:()=>w});var s=a(72791),i=a(43360),t=a(95070),n=a(89743),r=a(2677),o=a(36638),d=a(7692),c=a(78820),m=a(2002),h=a(36161),x=a(39126),u=a(59513),p=a.n(u),j=(a(68639),a(68324)),v=a(59434),F=a(35205),b=a(45225),y=a(63524),g=a(52802),N=a(72426),f=a.n(N),A=a(80184);function w(){const[e,l]=(0,s.useState)(!1),[a,u]=(0,s.useState)(null),[N,w]=(0,s.useState)(),[S,C]=(0,s.useState)(),[P,k]=(0,s.useState)(!1),D=(0,s.useRef)(null),Z=(0,v.I0)(),{user:z}=(0,v.v9)((e=>e.auth)),{allPrescription:I}=(0,v.v9)((e=>null===e||void 0===e?void 0:e.patientPrescription)),T=e=>{l(!0),w(e)},M=[{dataField:"prescriptionId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"medicine",text:"Medication",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"allergies",text:"Allergy",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"quantity",text:"Quantity",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"action",text:"Action",sort:!1,formatter:(e,l)=>(0,A.jsx)(A.Fragment,{children:(0,A.jsx)(c.w8I,{style:{color:"blue",cursor:"pointer"},onClick:()=>T(l)})}),headerStyle:{backgroundColor:"#F1F1F1"}}],L={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,a)=>(0,A.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,A.jsxs)("b",{children:[" ",e," "]})," to ",(0,A.jsx)("b",{children:l})," out of ",(0,A.jsxs)("b",{children:[a," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"6",value:10}]};return(0,s.useEffect)((()=>{const e={patientId:null===z||void 0===z?void 0:z.userId,search:S||null,isPagination:!0,isOnlineForm:P,prescribedDate:a?f()(a).format("YYYY-MM-DD"):null};Z((0,j.q9)({finalData:e}))}),[Z,null===z||void 0===z?void 0:z.userId,S,a,P]),(0,A.jsxs)(A.Fragment,{children:[(0,A.jsxs)("div",{className:"usermanagement-mainclass",children:[(0,A.jsx)(i.Z,{variant:"primary",onClick:()=>k(!1),className:"Admin-Tabs-All me-2 mb-2 ".concat(!1===P?"nav-btn-active":"nav-btn"),children:"Appointment Prescriptions"}),(0,A.jsx)(i.Z,{variant:"primary",onClick:()=>k(!0),className:"Admin-Tabs-All me-2 mb-2 ".concat(!0===P?"nav-btn-active":"nav-btn"),children:"Online Form Prescriptions"})]}),(0,A.jsxs)("div",{className:"Prescription-Main-Class patient-date-wrapper",children:[(0,A.jsx)(t.Z,{className:"shadow-sm mt-4",children:(0,A.jsxs)(A.Fragment,{children:[(0,A.jsxs)(n.Z,{className:"px-4 pt-3",children:[(0,A.jsx)(r.Z,{xl:3,sm:6,children:(0,A.jsxs)("span",{className:"d-flex align-self-center",children:[(0,A.jsx)(o.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&C(e.target.value)},onChange:e=>{"Enter"===e.key&&C(e.target.value)},type:"text",placeholder:"Search",className:"mb-3 search-field-spacing","aria-label":"Search"}),(0,A.jsx)(d.Goc,{size:22,className:"searchbar-icon"})]})}),(0,A.jsxs)(r.Z,{xl:9,sm:6,className:"d-flex flex-wrap align-self-center justify-content-end pe-0",children:[(0,A.jsx)(p(),{selected:a,onChange:e=>u(e),dateFormat:"dd MMM yyyy",placeholderText:"Date",className:"custom-field-picker invoice-cd-w px-2 mb-3"}),(0,A.jsx)(x.zlR,{size:18,style:{position:"relative",right:"29px",top:"15px",color:"#999999"}})]})]}),(0,A.jsx)("span",{className:"doctor-datatable",children:(0,A.jsx)(m.Z,{columns:M,data:I||[],keyField:"id",id:"bar",pagination:(0,h.ZP)(L),bordered:!1,wrapperClasses:"table-responsive"})})]})}),(0,A.jsx)(F.Z,{viewPresctionData:N,handleClose:()=>l(!1),show:e,onDownload:e=>{l(!1),setTimeout((function(){var e;null===D||void 0===D||null===(e=D.current)||void 0===e||e.click()}),1e3)},setSelectedData:u}),(0,A.jsx)(b.ZP,{trigger:(0,A.jsxs)("button",{ref:D,className:"border-0 px-3 py-2 rounded-2 d-none",children:[(0,A.jsx)(y.bAs,{size:20})," Download PDF"]}),children:(0,A.jsx)(g.Z,{prescriptionData:N})})]})]})}}}]);
//# sourceMappingURL=9049.b71ce6e5.chunk.js.map