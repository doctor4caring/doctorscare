"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[7714],{43426:(e,n,l)=>{l.d(n,{Z:()=>o});l(72791);var s=l(95070),i=l(72426),t=l.n(i),a=l(80184);function o(e){const{name:n,genderInfo:l,gender:i,dobInfo:o,dob:d,professionInfo:r,profession:c,currentLocationInfo:m,currentLocation:u,patientLocalGPInfo:p,patientLocalGP:x,emailInfo:v,email:h,phoneInfo:j,phone:f,specialityInfo:N,speciality:b,pharmacyInfo:w,pharmacy:I,locationInfo:A,location:g,nextOfKinName:y,nextOfKinNumber:F,nextOfKinNameInfo:S,nextOfKinNumberInfo:P,image:L}=e;return(0,a.jsx)(s.Z,{className:"generic-card",children:(0,a.jsxs)(s.Z.Body,{className:"p-0 main-personalprofile position-relative",children:[(0,a.jsx)("div",{className:"ds-top"}),(0,a.jsxs)("div",{className:"position-relative",children:[(0,a.jsx)("div",{className:"avatar-holder upload_pic profile_upload profileContent",children:(0,a.jsx)("img",{src:L||"https://ui-avatars.com/api/?name=".concat("".concat(n),"&background=000071&color=fff"),alt:"Patient"})}),(0,a.jsx)("div",{className:"name",children:n||"N/A"})]}),(0,a.jsxs)("div",{className:"mx-4 card-content patient-personal-details",children:[l&&(0,a.jsxs)(a.Fragment,{children:[" ",(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between pt-3",children:[(0,a.jsx)("p",{children:"Gender"}),(0,a.jsx)("p",{children:i||"N/A"})]}),(0,a.jsx)("hr",{})]}),o&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"D.O.B"}),(0,a.jsx)("p",{children:t()(d).format("MM/DD/YYYY")})]}),(0,a.jsx)("hr",{})]}),A&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Location"}),(0,a.jsx)("p",{children:g||"N/A"})]}),(0,a.jsx)("hr",{})]}),r&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Profession/Occupation:"}),(0,a.jsx)("p",{children:c||"N/A"})]}),(0,a.jsx)("hr",{})]}),m&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Current Location"}),(0,a.jsx)("p",{children:u||"N/A"})]}),(0,a.jsx)("hr",{})]}),p&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Patient Local GP"}),(0,a.jsx)("p",{children:x||"N/A"})]}),(0,a.jsx)("hr",{})]}),v&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Email"}),(0,a.jsx)("p",{children:h||"N/A"})]}),(0,a.jsx)("hr",{})]}),w&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Pharmacy"}),(0,a.jsx)("p",{children:I||"N/A"})]}),(0,a.jsx)("hr",{})]}),j&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Phone"}),(0,a.jsx)("p",{children:f||"N/A"})]}),(0,a.jsx)("hr",{})]}),S&&(0,a.jsxs)(a.Fragment,{children:[(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Next of Kin Name"}),(0,a.jsx)("p",{children:y||"N/A"})]}),(0,a.jsx)("hr",{})]}),P&&(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Next of Kin Number"}),(0,a.jsx)("p",{children:F||"N/A"})]}),N&&(0,a.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,a.jsx)("p",{children:"Speciality"}),(0,a.jsx)("p",{children:b||"N/A"})]})]})]})})}},57714:(e,n,l)=>{l.r(n),l.d(n,{default:()=>g});var s=l(72791),i=l(89743),t=l(2677),a=l(95070),o=l(11087),d=l(84373),r=l(43426),c=l(59434),m=l(36638),u=l(43360),p=l(3063),x=l(46587),v=l(61134),h=l(79243),j=l(57689),f=l(3810),N=l(88135),b=l(80184);function w(e){let{show:n,onClose:l}=e;const{register:s,handleSubmit:i}=(0,v.cI)(),t=JSON.parse(localStorage.getItem("family_doc_app")),{patientOnlinePrescForm:a}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.patientOnlinePresc)),o=(0,c.I0)(),d=(0,j.s0)();function r(){d(f.m.DOCTOR_PRESCRIPTION_DASHBOARD)}return(0,b.jsx)(b.Fragment,{children:(0,b.jsx)(N.Z,{show:n,onHide:l,centered:!0,size:"lg",className:"doctor-medication-modal",backdrop:"static",children:(0,b.jsxs)(m.Z,{onSubmit:i((function(e){var n,l;const s={patientFormStatusId:null===a||void 0===a||null===(n=a.data)||void 0===n||null===(l=n[0])||void 0===l?void 0:l.patientFormStatusId,doctorId:null===t||void 0===t?void 0:t.userId,formStatusId:502,rejectedReason:null===e||void 0===e?void 0:e.reasonOfRejected};o((0,h.E$)({finalData:s,onCreateSuccess:r}))})),children:[(0,b.jsx)(N.Z.Header,{closeButton:!0,children:(0,b.jsx)(N.Z.Title,{className:"prescription-modal-title",children:"Prescription"})}),(0,b.jsx)(N.Z.Body,{className:"",children:(0,b.jsxs)(m.Z.Group,{className:"mb-3",controlId:"formBasicLabel1",children:[(0,b.jsx)(m.Z.Label,{className:"label-primary mb-0",children:"Reason of Rejection"}),(0,b.jsx)(m.Z.Control,{as:"textarea",placeholder:"Type Here...",...s("reasonOfRejected",{required:!0}),rows:5,className:"pt-2",style:{height:"200px",whiteSpace:"pre-wrap"},maxLength:250})]})}),(0,b.jsx)(N.Z.Footer,{className:"d-flex justify-content-center",children:(0,b.jsx)(u.Z,{type:"submit",className:"w-50 border-0",style:{background:"hsl(240, 100%, 22.15686274509804%)"},children:"Save"})})]})})})}const I=function(){var e,n,l,i,t,a,o,d,r,N,I,A;const{handleSubmit:g}=(0,v.cI)(),[y,F]=(0,s.useState)(!1),S=(0,c.I0)(),P=(0,j.s0)(),L=(0,j.TH)();console.log("location",L);const Z=JSON.parse(localStorage.getItem("family_doc_app")),{patientOnlinePrescForm:O,isSuccess:C,isLoading:R,isError:_}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.patientOnlinePresc)),T=new URLSearchParams(window.location.search),k={};function D(){var e,n;P("".concat(f.m.DOCTOR_MEDICATION_FORM,"?patientId=").concat(null===k||void 0===k?void 0:k.patientId,"&formId=").concat(null===k||void 0===k?void 0:k.formId),{state:null===O||void 0===O||null===(e=O.data)||void 0===e||null===(n=e[0])||void 0===n?void 0:n.patientFormStatusId})}return T.forEach(((e,n)=>{k[n]=parseInt(e,10)})),(0,s.useEffect)((()=>{var e,n;const l={patientId:null===k||void 0===k?void 0:k.patientId,formId:null===k||void 0===k?void 0:k.formId,patientFormStatusId:null===L||void 0===L||null===(e=L.state)||void 0===e?void 0:e.patientFormStatusId,patientFormAttempt:null===L||void 0===L||null===(n=L.state)||void 0===n?void 0:n.patientFormAttempt};S((0,p.HL)(l))}),[S,null===k||void 0===k?void 0:k.patientId,null===k||void 0===k?void 0:k.formId,null===L||void 0===L||null===(e=L.state)||void 0===e?void 0:e.patientFormStatusId,null===L||void 0===L||null===(n=L.state)||void 0===n?void 0:n.patientFormAttempt]),(0,b.jsxs)(b.Fragment,{children:[(0,b.jsxs)("div",{className:"my-2",children:[(0,b.jsx)("h5",{className:"px-2 py-2 fw-bold header-border",children:"Patient Prescription Form"}),C?(0,b.jsx)(m.Z,{className:"mx-3",onSubmit:g((function(){var e,n;const l={patientFormStatusId:null===O||void 0===O||null===(e=O.data)||void 0===e||null===(n=e[0])||void 0===n?void 0:n.patientFormStatusId,doctorId:null===Z||void 0===Z?void 0:Z.userId,formStatusId:503,rejectedReason:""};S((0,h.E$)({finalData:l,onCreateSuccess:D}))})),children:(null===O||void 0===O||null===(l=O.data)||void 0===l?void 0:l.length)>0?(0,b.jsxs)(b.Fragment,{children:[null===O||void 0===O||null===(i=O.data)||void 0===i?void 0:i.map(((e,n)=>{var l,s,i;return(0,b.jsx)(b.Fragment,{children:(0,b.jsxs)(m.Z.Group,{className:"mb-3",controlId:"formQuestion".concat(n),children:[(0,b.jsxs)(m.Z.Label,{className:"label-primary mt-2 fw-bold",children:[(0,b.jsxs)("span",{className:"fw-bold",children:["Q.","".concat(n+1,".")," "]}),e.question]}),"Radio"===(null===e||void 0===e?void 0:e.answerType)?(0,b.jsx)(b.Fragment,{children:null===e||void 0===e||null===(l=e.formAnswersList)||void 0===l?void 0:l.map(((e,n)=>(0,b.jsxs)("p",{children:[(0,b.jsx)("span",{className:"fw-bold",children:"Ans: "}),null!==e&&void 0!==e&&e.answerLabel?null===e||void 0===e?void 0:e.answerLabel:"N/A"]})))}):"TextBox"===(null===e||void 0===e?void 0:e.answerType)?(0,b.jsx)(b.Fragment,{children:null===e||void 0===e||null===(s=e.formAnswersList)||void 0===s?void 0:s.map(((e,n)=>(0,b.jsxs)("p",{children:[(0,b.jsx)("span",{className:"fw-bold",children:"Ans: "}),null!==e&&void 0!==e&&e.textAnswerValue?null===e||void 0===e?void 0:e.textAnswerValue:"N/A"]})))}):"Checkbox"===(null===e||void 0===e?void 0:e.answerType)?(0,b.jsxs)("div",{className:"d-flex",children:[(0,b.jsx)("span",{className:"fw-bold me-1",children:"Ans:"}),(0,b.jsx)("p",{className:"d-inline-grid mb-0",children:null===e||void 0===e||null===(i=e.formAnswersList)||void 0===i?void 0:i.map(((n,l)=>(0,b.jsxs)("span",{className:"mb-0",children:[e.formAnswersList.length>1&&"".concat(l+1,". "),null!==n&&void 0!==n&&n.answerLabel?null===n||void 0===n?void 0:n.answerLabel:"N/A"]},l)))})]}):null]})})})),console.log("location?.state?.formStatus","Accepted"===!(null!==L&&void 0!==L&&null!==(t=L.state)&&void 0!==t&&t.formStatus)&&!(null!==L&&void 0!==L&&null!==(a=L.state)&&void 0!==a&&a.isPrescriptionAdded)),console.log("formStatus","Accepted"!==(null===L||void 0===L||null===(o=L.state)||void 0===o?void 0:o.formStatus)),console.log("isPrescriptionAdded",!(null!==L&&void 0!==L&&null!==(d=L.state)&&void 0!==d&&d.isPrescriptionAdded)),"Accepted"===(null===L||void 0===L||null===(r=L.state)||void 0===r?void 0:r.formStatus)||null!==L&&void 0!==L&&null!==(N=L.state)&&void 0!==N&&N.isPrescriptionAdded?"Accepted"!==(null===L||void 0===L||null===(I=L.state)||void 0===I?void 0:I.formStatus)||null!==L&&void 0!==L&&null!==(A=L.state)&&void 0!==A&&A.isPrescriptionAdded?null:(0,b.jsx)("div",{className:"d-flex justify-content-end",children:(0,b.jsx)(u.Z,{variant:"primary",type:"button",onClick:D,className:"Admin-Add-btn fw-bold",children:"Create Prescripiton"})}):(0,b.jsxs)("div",{className:"d-flex justify-content-end",children:[(0,b.jsx)(u.Z,{className:"Admin-Modal-CancelBtn fw-bold me-2",onClick:()=>F(!0),children:"Reject"}),(0,b.jsx)(u.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold",children:"Accept"})]})]}):(0,b.jsx)("p",{className:"text-center mt-3",children:"No Record Found"})}):R?(0,b.jsx)(x.Z,{}):_?(0,b.jsx)("p",{className:"text-center mt-3",children:"Network Error..."}):(0,b.jsx)("p",{className:"text-center mt-3",children:"No Record Found"})]}),(0,b.jsx)(w,{show:y,onClose:()=>F(!1)})]})};var A=l(36455);const g=function(){let e=new URLSearchParams(window.location.search).get("patientId");const n=(0,c.I0)(),{getPatientData:l}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.patient));return(0,s.useEffect)((()=>{const l={patientId:e};n((0,A._s)(l))}),[n,e]),(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("nav",{"aria-label":"breadcrumb",children:(0,b.jsxs)("ol",{className:"breadcrumb",children:[(0,b.jsx)("li",{className:"breadcrumb-item",children:(0,b.jsx)(o.rU,{to:"/doctor/online-prescription-forms",className:"text-decoration-none fs-5 color-99",children:"Online Prescription"})}),(0,b.jsx)(d.hjJ,{className:"mx-1 mt-2 color-99"}),(0,b.jsx)("li",{className:"breadcrumb-item active fs-5","aria-current":"page",style:{color:"#000071"},children:"Patient Form"})]})}),(0,b.jsxs)(i.Z,{className:"my-3 patient-details",children:[(0,b.jsx)(t.Z,{xl:3,lg:4,md:4,children:(0,b.jsx)("div",{className:"shadow-sm",children:(0,b.jsx)(r.Z,{name:null!==l&&void 0!==l&&l.firstName?"".concat(null===l||void 0===l?void 0:l.firstName," ").concat(null===l||void 0===l?void 0:l.lastName):"N/A",genderInfo:"true",gender:null!==l&&void 0!==l&&l.gender?null===l||void 0===l?void 0:l.gender:"N/A",dobInfo:"true",dob:null!==l&&void 0!==l&&l.dob?null===l||void 0===l?void 0:l.dob.split("T")[0]:"N/A",locationInfo:"true",location:null!==l&&void 0!==l&&l.currentAddress?null===l||void 0===l?void 0:l.currentAddress:"N/A",currentLocationInfo:"true",currentLocation:null!==l&&void 0!==l&&l.currentAddress?null===l||void 0===l?void 0:l.currentAddress:"N/A",patientLocalGPInfo:"true",patientLocalGP:null!==l&&void 0!==l&&l.patientLocalGP?null===l||void 0===l?void 0:l.patientLocalGP:"N/A",emailInfo:"true",email:null!==l&&void 0!==l&&l.email?null===l||void 0===l?void 0:l.email:"N/A",pharmacyInfo:"true",pharmacy:"Clinix",phoneInfo:"true",phone:null!==l&&void 0!==l&&l.phoneNumber?null===l||void 0===l?void 0:l.phoneNumber:"N/A",image:null===l||void 0===l?void 0:l.imageUrl})})}),(0,b.jsx)(t.Z,{xl:9,lg:8,md:8,children:(0,b.jsx)(a.Z,{className:"shadow-sm px-4 py-4 h-100",children:(0,b.jsx)(I,{})})})]})]})}}}]);
//# sourceMappingURL=7714.2f0de257.chunk.js.map