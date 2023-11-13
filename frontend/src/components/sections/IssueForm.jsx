import React from "react";

export default function IssueForm({
  contacts,
  data,
  identity,
  changeHandle,
  handlePage,
  handleChangeDrawerIsDrawee,
  handleChangeDrawerIsPayee,
}) {
  const handleSubmition = (e) => {
    e.preventDefault();

    const form_data = new FormData();
    form_data.append("bill_jurisdiction", data.bill_jurisdiction);
    form_data.append("place_of_drawing", data.place_of_drawing);
    form_data.append("amount_numbers", data.amount_numbers);
    form_data.append("language", data.language);
    form_data.append("drawee_name", data.drawee_name);
    form_data.append("payee_name", data.payee_name);
    form_data.append("place_of_payment", data.place_of_payment);
    form_data.append("maturity_date", data.maturity_date);
    form_data.append("drawer_is_payee", data.drawer_is_payee);
    form_data.append("drawer_is_drawee", data.drawer_is_drawee);
    fetch("http://localhost:8000/bill/issue", {
      method: "POST",
      body: form_data,
      mode: "no-cors",
    })
      .then((response) => {
        console.log(response);
      })
      .catch((err) => err);

      handlePage("home");
  };

  let listContacts = contacts.map((contact) => {
    return <option key={contact.name}>{contact.name}</option>;
  });

  return (
    <form className="form" onSubmit={handleSubmition}>
      <div className="form-input">
        <label htmlFor="maturity_date">Maturity date</label>
        <div className="form-input-row">
          <input
            className="drop-shadow"
            id="maturity_date"
            name="maturity_date"
            value={data.maturity_date}
            onChange={changeHandle}
            type="date"
            placeholder="16 May 2023"
            required
          />
        </div>
      </div>
      <div className="flex-row">
        <div className="form-input flex-grow">
          <label htmlFor="drawee_name">to the order of</label>
          <div className="form-input-row">
            <select
              className="select-class"
              disabled={data.drawer_is_payee}
              style={{ appereance: "none" }}
              id="payee_name"
              name="payee_name"
              value={data.payee_name}
              onChange={changeHandle}
              placeholder="Payee Company, Zurich"
            >
              <option value=""></option>
              {listContacts}
            </select>
          </div>
        </div>
        <label className="flex-col align-center" htmlFor="drawer_is_payee">
          <span>ME</span>
          <div className="form-input-row">
            <input
              disabled={data.drawer_is_drawee || data.payee_name}
              type="checkbox"
              id="drawer_is_payee"
              name="drawer_is_payee"
              checked={data.drawer_is_payee}
              onChange={handleChangeDrawerIsPayee}
            />
            <span
              className="check-boxes"
              style={{
                borderColor: `#${data.drawer_is_payee ? "F7931A" : "545454"}`,
              }}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="15"
                height="12"
                viewBox="0 0 15 12"
                fill="none"
              >
                <path
                  fill-rule="evenodd"
                  clip-rule="evenodd"
                  d="M14.1757 0.762852C14.5828 1.13604 14.6104 1.76861 14.2372 2.17573L5.98716 11.1757C5.79775 11.3824 5.53031 11.5 5.25001 11.5C4.9697 11.5 4.70226 11.3824 4.51285 11.1757L0.762852 7.08482C0.389659 6.6777 0.417162 6.04514 0.824281 5.67194C1.2314 5.29875 1.86397 5.32625 2.23716 5.73337L5.25001 9.02011L12.7629 0.824281C13.136 0.417162 13.7686 0.389659 14.1757 0.762852Z"
                  fill={`#${data.drawer_is_payee ? "F7931A" : "545454"}`}
                />
              </svg>
            </span>
          </div>
        </label>
      </div>
      <div className="form-input">
        <label htmlFor="amount_numbers">the sum of</label>
        <div className="form-input-row">
          <span className="select-opt">
            <select
              style={{
                appereance: "none",
                MozAppearance: "none",
                WebkitAppearance: "none",
                textTransform: "uppercase",
              }}
              className="form-select"
              id="currency_code"
              name="currency_code"
              onChange={changeHandle}
              placeholder="SATS"
              required
            >
              <option value={data.currency_code}>sats</option>
            </select>
          </span>
          <input
            className="drop-shadow"
            name="amount_numbers"
            value={data.amount_numbers}
            onChange={changeHandle}
            type="number"
            placeholder="10000"
            required
          />
        </div>
      </div>
      <div className="flex-row">
        <div className="form-input flex-grow">
          <label htmlFor="drawee_name">Drawee</label>
          <div className="form-input-row">
            <select
              disabled={data.drawer_is_drawee}
              style={{
                appereance: "none",
                MozAppearance: "none",
                WebkitAppearance: "none",
              }}
              id="drawee_name"
              name="drawee_name"
              placeholder="Drawee Company, Vienna"
              value={data.drawee_name}
              onChange={changeHandle}
            >
              <option value=""></option>
              {listContacts}
            </select>
          </div>
        </div>
        <label className="flex-col align-center" htmlFor="drawer_is_drawee">
          <span>ME</span>
          <div className="form-input-row">
            <input
              disabled={data.drawer_is_payee || data.drawee_name}
              type="checkbox"
              id="drawer_is_drawee"
              name="drawer_is_drawee"
              onChange={handleChangeDrawerIsDrawee}
              checked={data.drawer_is_drawee}
            />
            <span
              className="check-boxes"
              style={{
                borderColor: `#${data.drawer_is_drawee ? "F7931A" : "545454"}`,
              }}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="15"
                height="12"
                viewBox="0 0 15 12"
                fill="none"
              >
                <path
                  fill-rule="evenodd"
                  clip-rule="evenodd"
                  d="M14.1757 0.762852C14.5828 1.13604 14.6104 1.76861 14.2372 2.17573L5.98716 11.1757C5.79775 11.3824 5.53031 11.5 5.25001 11.5C4.9697 11.5 4.70226 11.3824 4.51285 11.1757L0.762852 7.08482C0.389659 6.6777 0.417162 6.04514 0.824281 5.67194C1.2314 5.29875 1.86397 5.32625 2.23716 5.73337L5.25001 9.02011L12.7629 0.824281C13.136 0.417162 13.7686 0.389659 14.1757 0.762852Z"
                  fill={`#${data.drawer_is_drawee ? "F7931A" : "545454"}`}
                />
              </svg>
            </span>
          </div>
        </label>
      </div>
      <div className="form-input">
        <label htmlFor="place_of_drawing">Place of drawing</label>
        <div className="form-input-row">
          <input
            id="place_of_drawing"
            name="place_of_drawing"
            value={data.place_of_drawing}
            onChange={changeHandle}
            type="text"
            placeholder="Zurich"
            required
          />
        </div>
      </div>
      <div className="form-input">
        <label htmlFor="place_of_payment">Place of payment</label>
        <div className="form-input-row">
          <input
            id="place_of_payment"
            name="place_of_payment"
            value={data.place_of_payment}
            onChange={changeHandle}
            type="text"
            placeholder="London"
            required
          />
        </div>
      </div>
      <div className="form-input">
        <label htmlFor="bill_jurisdiction">Bill jurisdiction</label>
        <div className="form-input-row">
          <input
            id="bill_jurisdiction"
            name="bill_jurisdiction"
            value={data.bill_jurisdiction}
            onChange={changeHandle}
            type="text"
            placeholder="UK"
            required
          />
        </div>
      </div>
      <div className="form-input" hidden={true}>
        <label htmlFor="language">Language</label>
        <div className="form-input-row">
          <input
            id="language"
            name="language"
            value={data.language}
            onChange={changeHandle}
            type="text"
            required
            readOnly={true}
          />
        </div>
      </div>
      {/*<div className="form-input">*/}
      {/*  <label htmlFor="maturity_date">Date of issue</label>*/}
      {/*  <div className="form-input-row">*/}
      {/*    <input*/}
      {/*      className="drop-shadow"*/}
      {/*      id="date_of_issue"*/}
      {/*      name="date_of_issue"*/}
      {/*      value={data.date_of_issue}*/}
      {/*      onChange={changeHandle}*/}
      {/*      type="date"*/}
      {/*      placeholder="16 May 2023"*/}
      {/*      required*/}
      {/*    />*/}
      {/*  </div>*/}
      {/*</div>*/}
      <input className="btn" type="submit" value="Issue bill" />
    </form>
  );
}
