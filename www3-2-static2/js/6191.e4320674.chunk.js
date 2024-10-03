"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6191],{7872:(e,a,t)=>{t.r(a),t.d(a,{default:()=>N});var l=t(72791),r=t(89743),n=t(2677),s=t(36638),i=t(95070),d=t(43360),o=t(7692),c=t(78820),m=t(57689),h=t(2002),u=t(36161),p=(t(68639),t(3810)),x=t(79243),v=t(59434),f=t(80184);function F(){var e;const[a,t]=(0,l.useState)(),r=(0,v.I0)(),n=(0,m.s0)(),F=JSON.parse(localStorage.getItem("family_doc_app")),{getAllAdminOnlinePrescripionForm:N}=(0,v.v9)((e=>(null===e||void 0===e?void 0:e.onlinePrescriptionForm)||[]));(0,l.useEffect)((()=>{const e={Search:a||""};r((0,x.LB)(e))}),[r,a]);const j=[{dataField:"formId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"title",text:"Disease Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"createdDate",text:"Created Date",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"isActive",text:"Status",sort:!1,headerStyle:{backgroundColor:"#F1F1F1"},headerAlign:"center",formatter:e=>(0,f.jsx)("p",{className:"mb-0 text-center py-1 custom-width-class active-status",children:"Active"})},{dataField:"action",text:"Action",sort:!1,headerAlign:"center",formatter:(e,a)=>(0,f.jsxs)("div",{className:"d-flex justify-content-evenly",children:[(0,f.jsx)(c.w8I,{onClick:()=>(e=>{1===(null===F||void 0===F?void 0:F.roleId)?n("".concat(p.m.SUPERADMIN_QUESTIONNAIRE,"?disease=").concat(null===e||void 0===e?void 0:e.formId)):4===(null===F||void 0===F?void 0:F.roleId)&&n("".concat(p.m.ADMIN_QUESTIONNAIRE,"?disease=").concat(null===e||void 0===e?void 0:e.formId))})(a),className:"table-action text-cursor-pointer"}),(0,f.jsx)(s.Z.Check,{type:"switch",defaultChecked:!0})]}),headerStyle:{backgroundColor:"#F1F1F1"}}],I={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,a,t)=>(0,f.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,f.jsxs)("b",{children:[" ",e," "]})," to ",(0,f.jsx)("b",{children:a})," out of ",(0,f.jsxs)("b",{children:[t," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,f.jsx)(f.Fragment,{children:(0,f.jsx)(i.Z,{className:"shadow-sm patient-card patient-profile-wrapper",children:(0,f.jsxs)(f.Fragment,{children:[(0,f.jsxs)("div",{className:"d-flex justify-content-between mt-3 mx-3",children:[(0,f.jsxs)("span",{className:"d-flex",children:[(0,f.jsx)(s.Z.Control,{type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing","aria-label":"Search",onKeyDown:e=>{"Enter"===e.key&&t(e.target.value)},onChange:e=>{"Enter"===e.key&&t(e.target.value)}}),(0,f.jsx)(o.Goc,{size:22,className:"searchbar-icon"})]}),(0,f.jsx)("span",{children:(0,f.jsx)(d.Z,{variant:"primary",type:"button",className:"Admin-Add-btn fw-bold",onClick:()=>{1===(null===F||void 0===F?void 0:F.roleId)?n(p.m.SUPERADMIN_QUESTIONNAIRE):4===(null===F||void 0===F?void 0:F.roleId)&&n(p.m.ADMIN_QUESTIONNAIRE)},children:"Add"})})]}),(0,f.jsx)("span",{className:"doctor-datatable",children:(null===N||void 0===N||null===(e=N.data)||void 0===e?void 0:e.length)>0?(0,f.jsx)(h.Z,{columns:j,data:null!==N&&void 0!==N&&N.data?null===N||void 0===N?void 0:N.data:[],keyField:"formId",id:"formId",pagination:(0,u.ZP)(I),bordered:!1,wrapperClasses:"table-responsive"}):(0,f.jsx)("p",{className:"text-center",children:"No Record Found"})})]})})})}function N(){return(0,f.jsxs)(f.Fragment,{children:[(0,f.jsx)("h5",{children:"Questionnaire Forms"}),(0,f.jsx)(r.Z,{className:"my-3",children:(0,f.jsx)(n.Z,{xs:12,children:(0,f.jsx)(F,{})})})]})}},11701:(e,a,t)=>{t.d(a,{Ed:()=>n,UI:()=>r,XW:()=>s});var l=t(72791);function r(e,a){let t=0;return l.Children.map(e,(e=>l.isValidElement(e)?a(e,t++):e))}function n(e,a){let t=0;l.Children.forEach(e,(e=>{l.isValidElement(e)&&a(e,t++)}))}function s(e,a){return l.Children.toArray(e).some((e=>l.isValidElement(e)&&e.type===a))}},68639:()=>{}}]);
//# sourceMappingURL=6191.e4320674.chunk.js.map