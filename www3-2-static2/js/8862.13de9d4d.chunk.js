"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[8862],{45793:(e,s,l)=>{l.d(s,{Z:()=>i});var a=l(29086);const i=async e=>{const s=await(null===a.Z||void 0===a.Z?void 0:a.Z.post("/digitalOcean/post",e));return null===s||void 0===s?void 0:s.data}},17505:(e,s,l)=>{l.d(s,{c:()=>n});var a=l(3810),i=l(80184);function n(e){return(0,i.jsx)("div",{className:"error-message-field-generic",children:(0,i.jsx)("p",{className:"mb-1",children:e.message?e.message:a.p.SYSTEM_ERROR})})}},78862:(e,s,l)=>{l.r(s),l.d(s,{default:()=>F});var a=l(72791),i=l(59434),n=l(75737),o=l.n(n),d=(l(98404),l(47022)),r=l(89743),t=l(2677),c=l(95070),m=l(36957),u=l(36638),h=l(43360),x=l(61734),p=l(84373),j=l(56355),g=l(61134),N=l(51276),v=l.n(N),b=l(4053),f=l(73683),Z=l(45793),y=l(76053),A=l(78820),w=l(82962),I=l(80591),P=l(80184);function S(e){const{signatureMode:s,editingMode:l}=e,{handleSubmit:n}=(0,g.cI)(),[o,d]=(0,a.useState)(!0),[r,t]=(0,a.useState)(null),[c,m]=(0,a.useState)(null),[x,p]=(0,a.useState)(),[N,S]=(0,a.useState)(),C=(0,a.useRef)({}),L=(0,i.I0)(),k=JSON.parse(localStorage.getItem("family_doc_app")),{getUserData:F}=(0,i.v9)((e=>(null===e||void 0===e?void 0:e.userRole)||"")),U=e=>{e||d(!o)},E=()=>{s(!1),l(!0);const e={userId:null===k||void 0===k?void 0:k.userId};L((0,I.PR)(e))};return(0,P.jsxs)("div",{className:"px-5 py-4",children:[(0,P.jsx)("h5",{className:"fw-bold",children:"Signature"}),(0,P.jsxs)(u.Z,{onSubmit:n((function(){const e={doctorId:null===k||void 0===k?void 0:k.userId,doctorSignature:r?null===r||void 0===r?void 0:r.keyName:null===c||void 0===c?void 0:c.keyName};L((0,w.V5)({signatureURL:e,moveToNext:E}))})),children:[(0,P.jsx)(u.Z.Check,{type:"checkbox",id:"upload-picture",label:"Upload Picture",onChange:()=>U(o),checked:o,disabled:null===F||void 0===F?void 0:F.doctorSignature}),(0,P.jsx)(u.Z.Check,{type:"checkbox",id:"signature-pad",label:"Signature Pad",onChange:()=>U(!o),checked:!o,disabled:null===F||void 0===F?void 0:F.doctorSignature}),(0,P.jsx)("div",{className:"border py-4 rounded upload_pic",children:o?(0,P.jsxs)(P.Fragment,{children:[(0,P.jsxs)("label",{htmlFor:"signature-upload",className:"text-center w-100 pt-1",children:[(0,P.jsx)("img",{className:"mb-2 upload-icon",src:b.Z.UPLOAD_ICON,alt:"upload file"}),(0,P.jsx)("p",{className:"upload-text mb-1",children:"Upload a file"}),(0,P.jsx)("p",{className:"upload-text_small mb-0",children:"PNG, JPG, JPEG upto 2MB"})]}),(0,P.jsx)("input",{size:"small",type:"file",id:"signature-upload",name:"signature-upload",accept:"image/png, image/jpeg",onChange:e=>{(async e=>{let s=e.target.files[0];if(p(s),s){const e=s.name.lastIndexOf("."),l=s.name.slice(0,e),a=s.name.slice(e+1,s.name.length);(0,f.ZP)(s).then((e=>{const s={name:l,base64:e,fileExtension:"".concat(a)};(0,Z.Z)(s).then((e=>{e&&m(e)}))}))}})(e)}}),(0,P.jsx)("div",{className:"my-3",children:x&&(0,P.jsxs)("div",{className:"d-flex align-items-center mx-3",children:[(0,P.jsx)(y.hF6,{size:30,style:{color:"#745DED"}}),(0,P.jsx)("h6",{className:"file-name mb-0 ms-2",children:null===x||void 0===x?void 0:x.name}),(0,P.jsx)("span",{className:"mx-3",children:(0,P.jsx)(A.oHP,{size:18,onClick:()=>{p(null)}})})]})})]}):(0,P.jsxs)("div",{className:"w-100",children:[(0,P.jsxs)("div",{className:"d-flex justify-content-center",children:[(0,P.jsx)(v(),{ref:C,canvasProps:{className:"signatureCanvas rounded border me-3"}}),r?(0,P.jsx)("div",{className:"d-flex align-items-end",children:(0,P.jsx)("img",{src:null===r||void 0===r?void 0:r.baseUrl,alt:"my signature",style:{display:"block",border:"1px solid black",width:"150px",height:"100px"}})}):null]}),(0,P.jsxs)("div",{className:"mt-2 d-flex justify-content-center",children:[(0,P.jsxs)(h.Z,{onClick:()=>{const e=C.current.getTrimmedCanvas().toDataURL("image/png");e.substring(11,e.indexOf(";base64"));const s=e.split(";")[0].split("/")[1];S(!0);const l={name:"signatureImage",base64:e,fileExtension:"".concat(s)};(0,Z.Z)(l).then((e=>{e&&(t(e),S(!1))}))},style:{background:"#6045EB"},className:"me-2",children:[(0,P.jsx)(j.wEH,{})," Add Signature"]}),(0,P.jsx)(h.Z,{onClick:()=>t(C.current.clear()),type:"button",style:{background:"#6045EB"},children:"Clear"})]})]})}),(0,P.jsx)("div",{className:"w-100 d-flex justify-content-end mt-3",children:(0,P.jsx)(h.Z,{style:{background:"#6045EB"},type:"submit",disabled:!r&&!x,children:"Save"})})]})]})}var C=l(17505),L=l(16115);const k=function(e){const{getUserData:s}=e,l=(0,i.I0)(),[n,o]=(0,a.useState)(!1),[d,m]=(0,a.useState)(!1),[x,p]=(0,a.useState)(!1),{register:j,watch:N,handleSubmit:v,reset:b,formState:{errors:f}}=(0,g.cI)(),Z=(0,a.useRef)({});Z.current=N("password","");const y=()=>{b({oldPassword:""})};return(0,P.jsx)(t.Z,{lg:12,children:(0,P.jsx)("div",{children:(0,P.jsxs)(c.Z,{children:[(0,P.jsx)(c.Z.Img,{variant:"top",className:"Card-Image"}),(0,P.jsxs)(c.Z.Body,{className:"p-0",children:[(0,P.jsx)("div",{className:"d-flex align-items-center upload_pic",children:(0,P.jsx)("img",{src:(null===s||void 0===s?void 0:s.imageUrl)||"https://ui-avatars.com/api/?name=".concat("".concat(null===s||void 0===s?void 0:s.name),"&background=6045eb&color=fff"),alt:"",srcset:"",className:"img-fluid Profile-2 position-relative test-border"})}),(0,P.jsxs)(c.Z.Title,{className:"Personal-Information fw-bold",children:["Change Password",(0,P.jsx)("p",{className:"Password-text mt-3",style:{color:"#999999"},children:"Use a strong password. Don't use a password from another sites, or something too obvious like your pet's name."})]}),(0,P.jsx)(r.Z,{className:"pt-4 Password-Input-Spacing",children:(0,P.jsx)(u.Z,{className:"mt-5",onSubmit:v((function(e){const s={password:e.oldPassword,newPassword:e.password};l((0,L.Cp)({finalData:s,moveToNext:y}))})),children:(0,P.jsxs)(t.Z,{lg:6,md:6,sm:6,xs:10,children:[(0,P.jsxs)(u.Z.Group,{className:"mb-3 position-relative",controlId:"formBasicEmail",children:[(0,P.jsx)(u.Z.Label,{className:"fw-bold Form-label-Font",style:{color:"#1A1A1A"},children:"Old Password"}),(0,P.jsx)(u.Z.Control,{type:n?"text":"password",placeholder:"Password",className:"Field-Sizing",size:"lg",name:"oldPassword",...j("oldPassword",{required:!0})}),f.oldPassword&&(0,P.jsx)("p",{className:"text-danger",children:f.oldPassword.message}),(0,P.jsx)("div",{onClick:()=>o((e=>!e)),className:"eye-icon",children:n?(0,P.jsx)(A.Zju,{size:18}):(0,P.jsx)(A.I0d,{size:18})})]}),(0,P.jsxs)(u.Z.Group,{className:"mb-3 position-relative",controlId:"formBasicEmail",children:[(0,P.jsx)(u.Z.Label,{className:"fw-bold Form-label-Font",style:{color:"#1A1A1A"},children:"New Password"}),(0,P.jsx)(u.Z.Control,{type:d?"text":"password",placeholder:"Password",className:"Field-Sizing",size:"lg",name:"password",...j("password",{required:!0})}),f.password&&(0,P.jsx)("p",{className:"text-danger",children:f.password.message}),(0,P.jsx)("div",{onClick:()=>m((e=>!e)),className:"eye-icon",children:d?(0,P.jsx)(A.Zju,{size:18}):(0,P.jsx)(A.I0d,{size:18})})]}),(0,P.jsxs)(u.Z.Group,{className:"mb-3 position-relative",controlId:"formBasicEmail",children:[(0,P.jsx)(u.Z.Label,{className:"fw-bold Confirm-Password Form-label-Font",style:{color:"#1A1A1A"},children:"Confirm Password"}),(0,P.jsx)(u.Z.Control,{type:x?"text":"password",placeholder:"Password",name:"confirmPassword",size:"lg",...j("confirmPassword",{validate:e=>e===Z.current||"The passwords does not match"})}),f.confirmPassword&&(0,P.jsx)("p",{className:"text-danger",children:f.confirmPassword.message}),(0,P.jsx)("div",{onClick:()=>p((e=>!e)),className:"eye-icon",children:x?(0,P.jsx)(A.Zju,{size:18}):(0,P.jsx)(A.I0d,{size:18})})]}),(0,P.jsx)("div",{className:"d-grid gap-2",children:(0,P.jsx)(h.Z,{variant:"primary",size:"lg",className:"Save-password-button my-2",type:"submit",children:"Save Password"})})]})})})]})]})})})};const F=function(){const e=(0,i.I0)(),s=JSON.parse(localStorage.getItem("family_doc_app")),{getUserData:l}=(0,i.v9)((e=>e.userRole)),[n,N]=(0,a.useState)(!0),[v,b]=(0,a.useState)(null===l||void 0===l?void 0:l.phoneNumber),[y,A]=(0,a.useState)(),[w,F]=(0,a.useState)(),[U,E]=(0,a.useState)(!1),{register:R,handleSubmit:B,formState:{errors:T}}=(0,g.cI)();(0,a.useEffect)((()=>{const l={userId:null===s||void 0===s?void 0:s.userId};e((0,I.PR)(l))}),[e,null===s||void 0===s?void 0:s.userId]);const z=()=>{N(!0);const l={userId:null===s||void 0===s?void 0:s.userId};e((0,I.PR)(l))};return(0,P.jsx)("div",{className:"patient-profile",children:(0,P.jsx)("div",{className:"Profile_Main_Class",children:(0,P.jsx)(d.Z,{fluid:!0,children:(0,P.jsx)(x.Z.Container,{id:"left-tabs-example",defaultActiveKey:"first",children:(0,P.jsxs)(r.Z,{children:[(0,P.jsx)(t.Z,{lg:3,children:(0,P.jsx)(c.Z,{className:"card-height",children:(0,P.jsx)(c.Z.Body,{className:"p-0",children:(0,P.jsxs)(m.Z,{variant:"pills",className:"flex-column ",children:[(0,P.jsx)(m.Z.Item,{children:(0,P.jsx)(m.Z.Link,{eventKey:"first",className:"personal-information ps-4 mt-4 personal-info-tabs",children:(0,P.jsxs)("span",{className:"Personal-Info d-flex justify-content-between align-items-center",children:["Personal Information",(0,P.jsx)(p.hjJ,{className:"float-right Arrow-ForwardIcon"})]})})}),(0,P.jsx)("hr",{className:"horizontal-line"}),(0,P.jsx)(m.Z.Item,{children:(0,P.jsx)(m.Z.Link,{eventKey:"second",className:"personal-information ps-4 personal-info-tabs",children:(0,P.jsxs)("span",{className:"Personal-Info d-flex justify-content-between align-items-center",children:["Change Password",(0,P.jsx)(p.hjJ,{className:"float-right Arrow-ForwardIcon"})]})})})]})})})}),(0,P.jsx)(t.Z,{lg:9,children:(0,P.jsx)(c.Z,{className:"card-height",children:(0,P.jsx)(c.Z.Body,{className:"p-0",children:(0,P.jsxs)(x.Z.Content,{className:"p-0",children:[n?(0,P.jsx)(x.Z.Pane,{eventKey:"first",children:(0,P.jsx)(t.Z,{lg:12,children:(0,P.jsx)("div",{children:(0,P.jsxs)(c.Z,{children:[(0,P.jsx)(c.Z.Img,{variant:"top",className:"Card-Image"}),(0,P.jsxs)(c.Z.Body,{className:"p-0",children:[(0,P.jsx)("div",{className:"d-flex align-items-center upload_pic",children:(0,P.jsx)("img",{src:(null===l||void 0===l?void 0:l.imageUrl)||"https://ui-avatars.com/api/?name=".concat("".concat(null===l||void 0===l?void 0:l.name),"&background=6045eb&color=fff"),alt:"",srcset:"",className:"img-fluid Profile-2 position-relative test-border"})}),(0,P.jsxs)("button",{type:"button",className:"btn btn-light Edit-Button fw-bold text-decoration-none ",style:{color:" #6045EB"},onClick:()=>{N(!1)},children:[(0,P.jsx)(j.fmQ,{className:"me-3 fs-5"}),"Edit"]}),(0,P.jsx)(c.Z.Title,{className:"Personal-Information ms-5 ps-3 fw-bold",children:"Personal Information"}),(0,P.jsxs)(r.Z,{className:"ps-5 mt-5",children:[(0,P.jsxs)(t.Z,{lg:4,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label",children:"Name"}),(0,P.jsx)("h5",{style:{color:"#1A1A1A"},className:"Users-List fw-bold",children:null!==l&&void 0!==l&&l.firstName?"".concat(null===l||void 0===l?void 0:l.firstName," ").concat(null===l||void 0===l?void 0:l.lastName):"N/A"})]}),(0,P.jsxs)(t.Z,{lg:4,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label",children:"Gender"}),(0,P.jsx)("h5",{style:{color:"#1A1A1A"},className:"Users-List fw-bold",children:null!==l&&void 0!==l&&l.genderName?null===l||void 0===l?void 0:l.genderName:"N/A"})]}),(0,P.jsxs)(t.Z,{lg:4,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label",children:"Phone"}),(0,P.jsx)("h5",{style:{color:"#1A1A1A"},className:"Users-List fw-bold",children:null!==l&&void 0!==l&&l.phoneNumber?null===l||void 0===l?void 0:l.phoneNumber:"N/A"})]}),(0,P.jsxs)(t.Z,{lg:4,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label mt-4",children:"Medical Council Number"}),(0,P.jsx)("h5",{style:{color:"#1A1A1A"},className:"Users-List fw-bold",children:null!==l&&void 0!==l&&l.mcrn?null===l||void 0===l?void 0:l.mcrn:"N/A"})]}),(0,P.jsxs)(t.Z,{lg:4,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label mt-4",children:"Email"}),(0,P.jsx)("h5",{style:{color:"#1A1A1A"},className:"Users-List fw-bold",children:null!==l&&void 0!==l&&l.email?null===l||void 0===l?void 0:l.email:"N/A"})]})]}),(0,P.jsxs)(r.Z,{className:"ps-5",children:[(0,P.jsxs)(t.Z,{lg:4,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label mt-4",children:"Address"}),(0,P.jsx)("h5",{style:{color:"#1A1A1A"},className:"Users-List fw-bold",children:null!==l&&void 0!==l&&l.currentAddress?null===l||void 0===l?void 0:l.currentAddress:"N/A"})]}),(0,P.jsx)(t.Z,{lg:4,md:6,sm:12,children:(0,P.jsxs)("span",{className:"d-flex",children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label me-2",children:"Signature:"}),null!==l&&void 0!==l&&l.doctorSignature?(0,P.jsx)("span",{style:{display:"block",border:"1px solid black",width:"150px",height:"auto"},className:"mt-4",children:(0,P.jsx)("img",{src:null===l||void 0===l?void 0:l.doctorSignature,alt:"signature",width:"100%",height:"100px"})}):(0,P.jsx)("p",{className:"mb-0 Users-List fw-bold",style:{marginTop:"30px"},children:"N/A"})]})})]})]})]})})})}):(0,P.jsx)(x.Z.Pane,{eventKey:"first",children:(0,P.jsx)(t.Z,{lg:12,children:(0,P.jsxs)(c.Z,{children:[(0,P.jsx)(c.Z.Img,{variant:"top",className:"Card-Image"}),(0,P.jsxs)(c.Z.Body,{className:"p-0",children:[(0,P.jsxs)("div",{className:"d-flex align-items-center upload_pic",children:[(0,P.jsx)("img",{src:(null===y||void 0===y?void 0:y.baseUrl)||(null===l||void 0===l?void 0:l.imageUrl)||"https://ui-avatars.com/api/?name=".concat("".concat(null===l||void 0===l?void 0:l.name),"&background=6045eb&color=fff"),alt:"",className:"img-fluid Profile-2 position-relative test-border"}),(0,P.jsxs)(h.Z,{className:"change-button",style:{marginTop:"4rem"},children:[(0,P.jsx)("label",{htmlFor:"patient-pic",children:"Change"}),(0,P.jsx)(u.Z.Control,{onChange:e=>(async e=>{let s=e.target.files[0];if(s){const e=s.name.lastIndexOf("."),l=s.name.slice(0,e),a=s.name.slice(e+1,s.name.length);(0,f.ZP)(s).then((e=>{F(!0);const s={name:l,base64:e,fileExtension:"".concat(a)};(0,Z.Z)(s).then((e=>{e&&(A(e),F(!1))}))}))}})(e),type:"file",id:"patient-pic",name:"patientPicture",accept:"image/*"})]}),(0,P.jsx)(h.Z,{className:"remove-button border-0",style:{marginTop:"4rem"},onClick:()=>A(""),children:"Remove"})]}),(0,P.jsx)(c.Z.Title,{className:"Personal-Information ms-5 ps-3 fw-bold",children:"Personal Information"}),U?(0,P.jsx)(S,{signatureMode:E,editingMode:N}):(0,P.jsxs)(u.Z,{onSubmit:B((function(a){const i={userId:null===s||void 0===s?void 0:s.userId,roleId:null===s||void 0===s?void 0:s.roleId,firstName:a.firstName,lastName:a.lastName,genderId:+a.genderName,speciality:a.speciality,email:a.email,phoneNumber:v||(null!==l&&void 0!==l&&l.phoneNumber?null===l||void 0===l?void 0:l.phoneNumber:""),mcrn:a.mcrn,currentAddress:a.currentAddress,image:null!==y&&void 0!==y&&y.keyName?null===y||void 0===y?void 0:y.keyName:null!==l&&void 0!==l&&l.imageUrl?null===l||void 0===l?void 0:l.imageUrl:""};e((0,I.Nq)({finalData:i,onCreateSuccess:z,callBackFunc:()=>{e((0,L.hj)())}}))})),children:[(0,P.jsxs)(r.Z,{className:"ps-4 mt-5",children:[(0,P.jsxs)(t.Z,{xl:4,lg:6,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label",style:{color:"#1A1A1A",fontWeight:"bold"},children:"First Name"}),(0,P.jsx)(u.Z.Control,{name:"firstName",type:"text",placeholder:"John Smith",className:"Input-Height",...R("firstName"),defaultValue:null===l||void 0===l?void 0:l.firstName}),T.firstName&&(0,P.jsx)(C.c,{message:"This Field is Required"})]}),(0,P.jsxs)(t.Z,{xl:4,lg:6,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label",style:{color:"#1A1A1A",fontWeight:"bold"},children:"Last Name"}),(0,P.jsx)(u.Z.Control,{name:"lastName",type:"text",placeholder:"John Smith",className:"Input-Height",...R("lastName"),defaultValue:null===l||void 0===l?void 0:l.lastName}),T.lastName&&(0,P.jsx)(C.c,{message:"This Field is Required"})]}),(0,P.jsxs)(t.Z,{xl:4,lg:6,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label ps-0 pe-0",style:{color:"#1A1A1A",fontWeight:"bold"},children:"Gender"}),(0,P.jsxs)(u.Z.Select,{name:"genderName",className:"Input-Height Select-Dropdown-Sizing",...R("genderName"),defaultValue:null===l||void 0===l?void 0:l.genderName,children:[(0,P.jsx)("option",{value:101,children:"Male"}),(0,P.jsx)("option",{value:102,children:"Female"}),(0,P.jsx)("option",{value:103,children:"Other"})]}),T.genderName&&(0,P.jsx)(C.c,{message:"This Field is Required"})]}),(0,P.jsxs)(t.Z,{xl:4,lg:6,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label mt-4",style:{color:"#1A1A1A",fontWeight:"bold"},children:"Email"}),(0,P.jsx)(u.Z.Control,{name:"email",type:"email",placeholder:"patient@gmail.com",className:"Input-Height",...R("email",{pattern:/^[^@ ]+@[^@ ]+\.[^@ .]{2,}$/}),defaultValue:null===l||void 0===l?void 0:l.email}),T.email&&(0,P.jsx)(C.c,{message:"This Field is Required"})]}),(0,P.jsxs)(t.Z,{xl:4,lg:6,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label mt-4",style:{color:"#1A1A1A",fontWeight:"bold"},children:"Phone Number"}),(0,P.jsx)(o(),{className:"Phone-Number-FieldWidth border rounded",value:null===l||void 0===l?void 0:l.phoneNumber,onChange:e=>b("+".concat(e))}),T.phoneNumber&&(0,P.jsx)(C.c,{message:"This Field is Required"})]}),(0,P.jsxs)(t.Z,{xl:4,lg:6,md:6,sm:12,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label mt-4",style:{color:"#1A1A1A",fontWeight:"bold"},children:"Medical Council Number"}),(0,P.jsx)(u.Z.Control,{name:"mcrn",type:"text",placeholder:"788 988 98 888",className:"Input-Height",...R("mcrn"),defaultValue:null===l||void 0===l?void 0:l.mcrn}),T.mcrn&&(0,P.jsx)(C.c,{message:"This Field is Required"})]}),(0,P.jsxs)(t.Z,{lg:8,children:[(0,P.jsx)(u.Z.Label,{className:"Name-Label mt-4",style:{color:"#1A1A1A",fontWeight:"bold"},children:"Address"}),(0,P.jsx)(u.Z.Control,{name:"currentAddress",type:"text",placeholder:"4517 Washington Ave. Manchester, Kentucky 39495",className:"Address-Input-Height",...R("currentAddress"),defaultValue:null===l||void 0===l?void 0:l.currentAddress}),T.currentAddress&&(0,P.jsx)(C.c,{message:"This Field is Required"})]}),(0,P.jsx)(t.Z,{lg:4,className:"d-flex align-items-end",children:(0,P.jsxs)("span",{className:"d-flex ".concat(null!==l&&void 0!==l&&l.doctorSignature?"color-99":""),children:[(0,P.jsx)("p",{className:"mb-0 text-decoration-underline text-cursor-pointer ".concat(null!==l&&void 0!==l&&l.doctorSignature?"disabled":""),onClick:()=>{E(!0)},children:"Upload Signature"}),(0,P.jsx)("span",{style:{color:"#FF3A3A"},children:"*"})]})})]}),(0,P.jsxs)("div",{className:"my-3 d-flex justify-content-end",children:[(0,P.jsx)(h.Z,{onClick:()=>N(!0),className:" mt-3 Save-Changes-Btn",style:{background:"#eae5e5",borderColor:"#eae5e5",color:"#000"},children:"Cancel"}),(0,P.jsx)(h.Z,{className:" mt-3 Save-Changes-Btn",style:{background:"#6045EB"},type:"submit",children:"Save Changes"})]})]})]})]})})}),(0,P.jsx)(x.Z.Pane,{eventKey:"second","data-toggle":"tab",children:(0,P.jsx)(k,{getUserData:l})})]})})})})]})})})})})}}}]);
//# sourceMappingURL=8862.13de9d4d.chunk.js.map