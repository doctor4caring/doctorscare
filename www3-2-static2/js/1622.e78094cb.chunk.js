"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[1622],{17505:(e,a,s)=>{s.d(a,{c:()=>n});var l=s(3810),t=s(80184);function n(e){return(0,t.jsx)("div",{className:"error-message-field-generic",children:(0,t.jsx)("p",{className:"mb-1",children:e.message?e.message:l.p.SYSTEM_ERROR})})}},14045:(e,a,s)=>{s.d(a,{Z:()=>n});var l=s(88135),t=s(80184);function n(e){let{children:a,...s}=e;const{handleClose:n,show:d,title:o,className:r}=s;return(0,t.jsx)("div",{children:(0,t.jsxs)(l.Z,{show:d,onHide:n,className:r,backdrop:"static",children:[(0,t.jsx)(l.Z.Header,{className:"py-3",closeButton:!0,children:(0,t.jsx)(l.Z.Title,{className:"modalTitle",children:(0,t.jsx)("span",{className:"font-weight-600",children:o})})}),(0,t.jsx)(l.Z.Body,{children:a})]})})}},41622:(e,a,s)=>{s.r(a),s.d(a,{default:()=>C});var l=s(72791),t=s(43360),n=s(95070),d=s(89743),o=s(2677),r=s(36638),i=s(61734),c=s(19485),m=s(14045),u=s(53392),h=s(98148),x=s(82962),v=s(61134),f=s(59434),p=s(17505),j=s(80184);const b=function(e){const{handleClose:a,updateSlot:s}=e,{handleSubmit:n,register:i}=(0,v.cI)(),[c,m]=(0,l.useState)(""),[b,N]=(0,l.useState)(""),[Z,g]=(0,l.useState)(""),[y,S]=(0,l.useState)(""),[C,k]=(0,l.useState)([]),[w,D]=(0,l.useState)(""),T=(0,f.I0)(),{allSlots:E}=(0,f.v9)((e=>e.doctorSchedule)),F=null===E||void 0===E?void 0:E.filter((e=>!e.isBooked)),I=F.map((e=>e.startTime)),_=F.map((e=>e.endTime)),M=E.map((e=>({scheduleId:e.scheduleId,Fee:e.Fee}))),Y=e=>{const{value:a,checked:s}=e.target;k(s?e=>[...e,a]:e=>e.filter((e=>e!==a)))},B=()=>{a();const e={date:c,month:null};T((0,x.xG)(e))},O=(e,a)=>{const s=new Date("".concat(c," ").concat(e));let l=(new Date("".concat(c," ").concat(a))-s)/6e4;return l<0&&(l+=1440),l>=15};return(0,j.jsx)(j.Fragment,{children:(0,j.jsxs)(r.Z,{onSubmit:n((function(e){var a,l;const t={startDate:c,endDate:b,startTime:null===(a=(0,h.oA)(Z,c))||void 0===a?void 0:a.split("Z")[0],endTime:null===(l=(0,h.oA)(y,c))||void 0===l?void 0:l.split("Z")[0],noOfDoctors:1,daysOfWeek:C},n={startDate:c,endDate:b,fee:null===e||void 0===e?void 0:e.feeValue};T(s?(0,x.JZ)({updateFeeData:n,moveToNext:B}):(0,x.Y3)({finalData:t,moveToNext:B}))})),children:[(0,j.jsxs)("div",{className:"mb-3 border p-3 rounded modalCheckboxes",children:[(0,j.jsx)(r.Z.Check,{type:"checkbox",id:"",label:"Monday",className:"d-flex",value:"Monday",onChange:Y}),(0,j.jsx)(r.Z.Check,{type:"checkbox",id:"",label:"Tuesday",className:"d-flex",value:"Tuesday",onChange:Y}),(0,j.jsx)(r.Z.Check,{type:"checkbox",id:"",label:"Wednesday",className:"d-flex",value:"Wednesday",onChange:Y}),(0,j.jsx)(r.Z.Check,{type:"checkbox",id:"",label:"Thursday",className:"d-flex",value:"Thursday",onChange:Y}),(0,j.jsx)(r.Z.Check,{type:"checkbox",id:"",label:"Friday",className:"d-flex",value:"Friday",onChange:Y}),(0,j.jsx)(r.Z.Check,{type:"checkbox",id:"",label:"Saturday",className:"d-flex",value:"Saturday",onChange:Y}),(0,j.jsx)(r.Z.Check,{type:"checkbox",id:"",label:"Sunday",className:"d-flex",value:"Sunday",onChange:Y})]},"0"),(0,j.jsxs)(d.Z,{children:[(0,j.jsxs)(o.Z,{md:6,xl:6,children:[(0,j.jsxs)(r.Z.Group,{controlId:"formDate",className:"mb-3",children:[(0,j.jsx)(u.Z,{className:"fw-semibold fs-6",children:"Start Date"}),(0,j.jsx)(r.Z.Control,{type:"date",placeholder:"Select a date",className:"custom-date",value:c,min:(0,h.Ux)(),onChange:e=>{const a=e.target.value;m(a);const s=new Date(a);s.setDate(s.getDate());const l=s.toISOString().split("T")[0];b<l&&N(l)}})]}),(0,j.jsxs)(r.Z.Group,{controlId:"",className:"mb-3",children:[(0,j.jsx)(u.Z,{className:"fw-semibold fs-6",children:"Start Time"}),(0,j.jsx)(r.Z.Control,{type:"time",placeholder:"HH:MM",className:"custom-date",disabled:!c,value:Z||I[0],onChange:e=>g(e.target.value)})]})]}),(0,j.jsxs)(o.Z,{md:6,xl:6,children:[(0,j.jsxs)(r.Z.Group,{controlId:"formDate",className:"mb-3",children:[(0,j.jsx)(u.Z,{className:"fw-semibold fs-6",children:"End Date"}),(0,j.jsx)(r.Z.Control,{type:"date",placeholder:"Select a date",className:"custom-date",value:b,disabled:""===c,min:c,onChange:e=>N(e.target.value)})]}),(0,j.jsxs)(r.Z.Group,{controlId:"",className:"mb-3",children:[(0,j.jsx)(u.Z,{className:"fw-semibold fs-6",children:"End Time"}),(0,j.jsx)(r.Z.Control,{type:"time",placeholder:"HH:MM",className:"custom-date",min:Z,value:y||_[1],disabled:!Z,onChange:e=>{const a=e.target.value;S(a);const s=O(Z,a);D(s?"":"The appointment start time and end time should be at least 15 minutes apart.")}})]})]}),w&&(0,j.jsx)(p.c,{message:w}),(0,j.jsx)(o.Z,{md:6,xl:6,children:(0,j.jsxs)(r.Z.Group,{controlId:"formBasicEmail",children:[(0,j.jsx)(r.Z.Label,{className:"fw-bold",children:"Fee (\u20ac)"}),(0,j.jsx)(r.Z.Control,{size:"lg",type:"number",step:"0.01",placeholder:"Enter Fee (1.36)",min:0,...i("feeValue",{required:!0}),defaultValue:M.length>0?M[0].Fee:""})]})}),(0,j.jsx)("div",{className:"d-grid mt-4",children:(0,j.jsx)(t.Z,{className:"block primary_bg",variant:"primary",size:"lg",type:"submit",disabled:w,children:s?"Update Fee":"Create Slot"})})]})]})})};const N=function(e){const{handleClose:a,updateSlot:s}=e,{handleSubmit:n,register:i}=(0,v.cI)(),[c,m]=(0,l.useState)(""),[b,N]=(0,l.useState)(""),[Z,g]=(0,l.useState)(""),[y,S]=(0,l.useState)(""),C=(0,f.I0)(),{allSlots:k}=(0,f.v9)((e=>e.doctorSchedule)),w=null===k||void 0===k?void 0:k.filter((e=>!e.isBooked)),D=w.map((e=>e.startTime)),T=w.map((e=>e.endTime)),E=k.map((e=>({scheduleId:e.scheduleId,Fee:e.Fee}))),F=[];F.push(function(){let e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:new Date(b),a=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"en-US";return null===e||void 0===e?void 0:e.toLocaleDateString(a,{weekday:"long"})}());const I=()=>{a();const e={date:b,month:null};C((0,x.xG)(e))},_=(e,a)=>{const s=new Date("".concat(b," ").concat(e));let l=(new Date("".concat(b," ").concat(a))-s)/6e4;return l<0&&(l+=1440),l>=15};return(0,j.jsx)(r.Z,{onSubmit:n((function(e){var a,l;const t={startDate:b,endDate:b,startTime:null===(a=(0,h.oA)(Z,b))||void 0===a?void 0:a.split("Z")[0],endTime:null===(l=(0,h.oA)(c,b))||void 0===l?void 0:l.split("Z")[0],noOfDoctors:1,daysOfWeek:F,fee:null===e||void 0===e?void 0:e.feeValue},n={fee:null===e||void 0===e?void 0:e.feeValue};C(s?(0,x.JZ)({updateFeeData:n,moveToNext:I}):(0,x.Y3)({finalData:t,moveToNext:I}))})),children:(0,j.jsxs)(d.Z,{children:[(0,j.jsx)(o.Z,{xl:12,children:(0,j.jsxs)(r.Z.Group,{controlId:"formDate",className:"mb-3",children:[(0,j.jsx)(u.Z,{className:"fw-semibold fs-6",children:"Date"}),(0,j.jsx)(r.Z.Control,{type:"date",name:"date",placeholder:"Select a date",className:"custom-date",value:b,min:(0,h.Ux)(),onChange:e=>{const a=e.target.value;N(a),g((0,h.Xn)()),m(T[1])}})]})}),!1===s&&(0,j.jsxs)(j.Fragment,{children:[(0,j.jsx)(o.Z,{md:6,xl:6,children:(0,j.jsxs)(r.Z.Group,{controlId:"",className:"mb-3",children:[(0,j.jsx)(u.Z,{className:"fw-semibold fs-6",children:"Start Time"}),(0,j.jsx)(r.Z.Control,{type:"time",placeholder:"HH:MM",name:"startTime",className:"custom-date",min:b||(0,h.Xn)(),disabled:!b,value:Z||D[0],onChange:e=>g(e.target.value)})]})}),(0,j.jsx)(o.Z,{md:6,xl:6,children:(0,j.jsxs)(r.Z.Group,{controlId:"",className:"mb-3",children:[(0,j.jsx)(u.Z,{className:"fw-semibold fs-6",children:"End Time"}),(0,j.jsx)(r.Z.Control,{type:"time",placeholder:"HH:MM",className:"custom-date",name:"endTime",min:Z,value:c||T[1],disabled:!Z,onChange:e=>{const a=e.target.value;m(a);const s=_(Z,a);S(s?"":"The appointment start time and end time should be at least 15 minutes apart.")}})]})}),y&&(0,j.jsx)(p.c,{message:y})]}),(0,j.jsx)(o.Z,{md:6,xl:6,children:(0,j.jsxs)(r.Z.Group,{controlId:"formBasicEmail",children:[(0,j.jsx)(r.Z.Label,{className:"fw-bold",children:"Fee (\u20ac)"}),(0,j.jsx)(r.Z.Control,{size:"lg",type:"number",step:"0.01",placeholder:"Enter Fee (1.36)",min:0,...i("feeValue",{required:!0}),defaultValue:E.length>0?E[0].Fee:"",required:!0})]})}),(0,j.jsx)("div",{className:"d-grid mt-4",children:(0,j.jsx)(t.Z,{className:"block",variant:"primary primary_bg",size:"lg",type:"submit",disabled:y,children:s?"Update Fee":"Create Slot"})})]})})};function Z(e){let{children:a,...s}=e;const{show:l,handleClose:t,updateSlot:n}=s;return(0,j.jsx)("div",{id:"AddSlot_modal",className:"AddSlot_modal",children:(0,j.jsx)(m.Z,{className:"modal-lg",title:n?"Update Slot Fees":"Time Slot Creation",handleClose:t,show:l,children:(0,j.jsx)("div",{className:"px-2 pb-3 addSlot_content",children:(0,j.jsxs)(c.Z,{defaultActiveKey:"1",id:"uncontrolled-tab-example slot_tabs",className:"mb-1 slot_tabs",children:[(0,j.jsx)(i.Z,{eventKey:"1",className:"slot_tab",title:"Single Day",children:(0,j.jsx)(N,{handleClose:t,updateSlot:n})}),(0,j.jsx)(i.Z,{eventKey:"2",title:"Recurring",className:"slot_tab",children:(0,j.jsx)(b,{handleClose:t,updateSlot:n})})]})})})})}var g=s(4053),y=s(72426),S=s.n(y);const C=()=>{const e=(0,f.I0)(),{handleSubmit:a,register:s}=(0,v.cI)(),[i,c]=(0,l.useState)(S()(new Date).format("YYYY-MM-DD")),[u,h]=(0,l.useState)(!1),[p,b]=(0,l.useState)(!1),N=()=>b(!1),[y,C]=(0,l.useState)(!1),{allSlots:k}=(0,f.v9)((e=>e.doctorSchedule));(0,l.useEffect)((()=>{if(i){const a={date:i,month:null};e((0,x.xG)(a))}}),[e,i]);const w=function(){let e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:new Date(i),a=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"en-US";return null===e||void 0===e?void 0:e.toLocaleDateString(a,{weekday:"long"})}();let D=null===k||void 0===k?void 0:k.filter((e=>e.isBooked)),T=null===k||void 0===k?void 0:k.filter((e=>!e.isBooked));return(0,j.jsxs)(j.Fragment,{children:[(0,j.jsxs)("div",{className:"d-flex justify-content-between align-items-center mb-3 mobileFlex_Col",children:[(0,j.jsx)("h5",{children:"Created Slots"}),i>=S()(new Date).format("YYYY-MM-DD")&&(0,j.jsxs)("div",{children:[((null===k||void 0===k?void 0:k.length)>0&&(null===D||void 0===D?void 0:D.length)<=0||(null===T||void 0===T?void 0:T.length)>0)&&(0,j.jsx)(t.Z,{onClick:()=>{b(!0),C(!0)},className:"btn-primary primary_bg me-2",children:"Update Fees"}),(0,j.jsx)(t.Z,{onClick:()=>{h(!0),C(!1)},className:"btn-primary primary_bg",children:"Create Slot"})]})]}),(0,j.jsxs)(n.Z,{className:"slotsSection",children:[(0,j.jsxs)(n.Z.Body,{children:[(0,j.jsxs)(d.Z,{className:"d-flex justify-content-between align-items-center mb-4",children:[(0,j.jsx)(o.Z,{xl:2,lg:4,md:4,sm:6,children:(0,j.jsx)("div",{className:"",children:(0,j.jsx)(r.Z.Control,{type:"date",name:"dob",defaultValue:S()(new Date).format("YYYY-MM-DD"),className:"custom-date",onChange:e=>c(e.target.value)})})}),(0,j.jsx)(o.Z,{md:4,lg:4,className:"text-center",children:(0,j.jsxs)("h5",{className:"text-black fw-bold mb-0",children:[w," - ",S()(i).format("DD-MM-YYYY")]})}),(0,j.jsx)(o.Z,{md:4,sm:4,children:(0,j.jsxs)("div",{className:"d-flex justify-content-end radioGroup",children:[(0,j.jsxs)("div",{className:"d-flex align-items-center me-sm-4 me-2",children:[(0,j.jsx)("span",{className:"bookedSlot rounded-circle me-2",children:(0,j.jsx)("img",{className:"",src:g.Z.BOOKED_SLOT,alt:"booked"})}),(0,j.jsx)("span",{children:"Booked Slots"})]}),(0,j.jsxs)("div",{className:"d-flex align-items-center",children:[(0,j.jsx)("span",{className:"availableSlot rounded-circle me-2",children:(0,j.jsx)("img",{className:"",src:g.Z.AVAILABLE_SLOT,alt:"booked"})}),(0,j.jsx)("span",{children:"Available Slots"})]})]})})]}),(0,j.jsx)("div",{children:(0,j.jsx)("div",{className:"slotContainer mt-4 pt-3 ",children:null!==k&&(null===k||void 0===k?void 0:k.length)>0?null===k||void 0===k?void 0:k.map((e=>(0,j.jsxs)(t.Z,{className:"slot_btn".concat(null!==e&&void 0!==e&&e.isBooked?" booked":""),children:[null===e||void 0===e?void 0:e.startTime," - ",null===e||void 0===e?void 0:e.endTime]},null===e||void 0===e?void 0:e.startTime))):(0,j.jsx)("p",{className:"text-center",children:"No Slot Available"})})})]}),(0,j.jsx)(Z,{show:u,handleClose:()=>h(!1),updateSlot:y})]}),(0,j.jsx)(m.Z,{className:"modal-lg",title:"Update Slot Fees",handleClose:N,show:p,children:(0,j.jsx)(r.Z,{onSubmit:a((function(a){const s={fee:null===a||void 0===a?void 0:a.feeValue};e((0,x.JZ)({updateFeeData:s})),N()})),children:(0,j.jsxs)(d.Z,{children:[(0,j.jsx)(o.Z,{sx:12,children:(0,j.jsxs)(r.Z.Group,{controlId:"formBasicEmail",children:[(0,j.jsx)(r.Z.Label,{className:"fw-bold",children:"Fee (\u20ac)"}),(0,j.jsx)(r.Z.Control,{size:"lg",type:"number",step:"0.01",placeholder:"Enter Fee (1.36)",min:0,...s("feeValue",{required:!0}),required:!0})]})}),(0,j.jsx)("div",{className:"d-grid mt-4",children:(0,j.jsx)(t.Z,{className:"block",variant:"primary primary_bg",size:"lg",type:"submit",children:"Update Fee"})})]})})})]})}},95070:(e,a,s)=>{s.d(a,{Z:()=>F});var l=s(81694),t=s.n(l),n=s(72791),d=s(10162),o=s(80184);const r=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:l,as:n="div",...r}=e;return l=(0,d.vE)(l,"card-body"),(0,o.jsx)(n,{ref:a,className:t()(s,l),...r})}));r.displayName="CardBody";const i=r,c=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:l,as:n="div",...r}=e;return l=(0,d.vE)(l,"card-footer"),(0,o.jsx)(n,{ref:a,className:t()(s,l),...r})}));c.displayName="CardFooter";const m=c;var u=s(96040);const h=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:l,as:r="div",...i}=e;const c=(0,d.vE)(s,"card-header"),m=(0,n.useMemo)((()=>({cardHeaderBsPrefix:c})),[c]);return(0,o.jsx)(u.Z.Provider,{value:m,children:(0,o.jsx)(r,{ref:a,...i,className:t()(l,c)})})}));h.displayName="CardHeader";const x=h,v=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:l,variant:n,as:r="img",...i}=e;const c=(0,d.vE)(s,"card-img");return(0,o.jsx)(r,{ref:a,className:t()(n?"".concat(c,"-").concat(n):c,l),...i})}));v.displayName="CardImg";const f=v,p=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:l,as:n="div",...r}=e;return l=(0,d.vE)(l,"card-img-overlay"),(0,o.jsx)(n,{ref:a,className:t()(s,l),...r})}));p.displayName="CardImgOverlay";const j=p,b=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:l,as:n="a",...r}=e;return l=(0,d.vE)(l,"card-link"),(0,o.jsx)(n,{ref:a,className:t()(s,l),...r})}));b.displayName="CardLink";const N=b;var Z=s(27472);const g=(0,Z.Z)("h6"),y=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:l,as:n=g,...r}=e;return l=(0,d.vE)(l,"card-subtitle"),(0,o.jsx)(n,{ref:a,className:t()(s,l),...r})}));y.displayName="CardSubtitle";const S=y,C=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:l,as:n="p",...r}=e;return l=(0,d.vE)(l,"card-text"),(0,o.jsx)(n,{ref:a,className:t()(s,l),...r})}));C.displayName="CardText";const k=C,w=(0,Z.Z)("h5"),D=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:l,as:n=w,...r}=e;return l=(0,d.vE)(l,"card-title"),(0,o.jsx)(n,{ref:a,className:t()(s,l),...r})}));D.displayName="CardTitle";const T=D,E=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:l,bg:n,text:r,border:c,body:m=!1,children:u,as:h="div",...x}=e;const v=(0,d.vE)(s,"card");return(0,o.jsx)(h,{ref:a,...x,className:t()(l,v,n&&"bg-".concat(n),r&&"text-".concat(r),c&&"border-".concat(c)),children:m?(0,o.jsx)(i,{children:u}):u})}));E.displayName="Card";const F=Object.assign(E,{Img:f,Title:T,Subtitle:S,Body:i,Link:N,Text:k,Header:x,Footer:m,ImgOverlay:j})},96040:(e,a,s)=>{s.d(a,{Z:()=>t});const l=s(72791).createContext(null);l.displayName="CardHeaderContext";const t=l},19485:(e,a,s)=>{s.d(a,{Z:()=>f});s(72791);var l=s(80239),t=s(25561),n=s(36957),d=s(89102),o=s(94175),r=s(34886),i=s(84504),c=s(11701),m=s(3507),u=s(80184);function h(e){let a;return(0,c.Ed)(e,(e=>{null==a&&(a=e.props.eventKey)})),a}function x(e){const{title:a,eventKey:s,disabled:l,tabClassName:t,tabAttrs:n,id:r}=e.props;return null==a?null:(0,u.jsx)(o.Z,{as:"li",role:"presentation",children:(0,u.jsx)(d.Z,{as:"button",type:"button",eventKey:s,disabled:l,id:r,className:t,...n,children:a})})}const v=e=>{const{id:a,onSelect:s,transition:d,mountOnEnter:o=!1,unmountOnExit:v=!1,variant:f="tabs",children:p,activeKey:j=h(p),...b}=(0,l.Ch)(e,{activeKey:"onSelect"});return(0,u.jsxs)(t.Z,{id:a,activeKey:j,onSelect:s,transition:(0,m.Z)(d),mountOnEnter:o,unmountOnExit:v,children:[(0,u.jsx)(n.Z,{...b,role:"tablist",as:"ul",variant:f,children:(0,c.UI)(p,x)}),(0,u.jsx)(r.Z,{children:(0,c.UI)(p,(e=>{const a={...e.props};return delete a.title,delete a.disabled,delete a.tabClassName,delete a.tabAttrs,(0,u.jsx)(i.Z,{...a})}))})]})};v.displayName="Tabs";const f=v}}]);
//# sourceMappingURL=1622.e78094cb.chunk.js.map