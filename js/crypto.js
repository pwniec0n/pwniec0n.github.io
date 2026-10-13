const PBKDF2_ITERATIONS = 100000;


async function decrypt(
  encryptedData,
  password
) {

  const salt =
    base64ToBytes(
      encryptedData.salt
    );

  const iv =
    base64ToBytes(
      encryptedData.iv
    );

  const cipher =
    base64ToBytes(
      encryptedData.cipher
    );


  const key =
    await getKey(
      password,
      salt
    );


  const contentBytes =
    new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv
        },
        key,
        cipher
      )
    );


  return bytesToString(
    contentBytes
  );
}


async function getKey(
  password,
  salt
) {

  const passwordBytes =
    stringToBytes(password);


  const initialKey =
    await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      {
        name: "PBKDF2"
      },
      false,
      [
        "deriveKey"
      ]
    );


  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations:
        PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    initialKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    [
      "decrypt"
    ]
  );
}


function stringToBytes(str) {
  return new TextEncoder()
    .encode(str);
}


function bytesToString(bytes) {
  return new TextDecoder()
    .decode(bytes);
}


function base64ToBytes(base64) {
  return Uint8Array.from(
    atob(base64),
    char =>
      char.charCodeAt(0)
  );
}


function sleep(ms) {
  return new Promise(
    resolve =>
      setTimeout(resolve, ms)
  );
}


/*
 * innerHTML does not execute scripts.
 *
 * Replacing script nodes with newly-created
 * script elements activates scripts contained
 * in the decrypted HTML.
 */
function activateScripts(container) {

  const scripts =
    Array.from(
      container.querySelectorAll(
        "script"
      )
    );


  for (
    const oldScript of scripts
  ) {

    const newScript =
      document.createElement(
        "script"
      );


    for (
      const attribute
      of oldScript.attributes
    ) {

      newScript.setAttribute(
        attribute.name,
        attribute.value
      );
    }


    newScript.textContent =
      oldScript.textContent;


    oldScript.replaceWith(
      newScript
    );
  }
}


async function revealContent(
  password
) {

  const input =
    document.getElementById(
      "password-input"
    );


  try {

    if (
      typeof ct_serial ===
        "undefined" ||
      !ct_serial
    ) {
      throw new Error(
        "Encrypted content was not loaded."
      );
    }


    const encryptedData =
      JSON.parse(
        atob(ct_serial)
      );


    const decryptedText =
      await decrypt(
        encryptedData,
        password
      );


    const contents =
      document.getElementById(
        "contents"
      );


    contents.innerHTML =
      decryptedText;


    activateScripts(
      contents
    );


    /*
     * Successful-password feedback.
     */
    input.classList.remove(
      "error"
    );

    input.classList.add(
      "success"
    );


    await sleep(1000);


    /*
     * Hide landing-page content.
     */
    document
      .getElementById("about")
      .classList.add("hidden");


    document
      .getElementById(
        "password-container"
      )
      .classList.add("hidden");


    /*
     * Switch the whole layout into its
     * unlocked state.
     *
     * CSS now controls logo resizing and
     * its relationship to the content card.
     */
    document
      .getElementById(
        "site-container"
      )
      .classList.add(
        "unlocked"
      );


    /*
     * Bring the protected-content card in.
     */
    document
      .getElementById(
        "render-container"
      )
      .classList.remove(
        "above"
      );


    /*
     * Don't retain the password.
     */
    input.value = "";

    /*
      Add form toggle stuff
    */
    // Javascript to toggle the form visibility 
    function initializeFormToggle() {
      console.log("DOM state:", document.readyState);
      console.log("Current page:", window.location.pathname);
        const formToggle = document.getElementById("formToggle");
        const formContent = document.getElementById("formContent");
        const formToggleText = document.getElementById("formToggleText");
        const formToggleIcon = document.getElementById("formToggleIcon");

        if ( !formToggleText || !formToggleIcon) {
            console.error(" toggle elements not found!");
            return;
        }

        formToggle.addEventListener("click", () => {
            const isOpen = formContent.classList.toggle("open");

            formToggleText.textContent = isOpen
                ? "Minimize Form"
                : "Open Form";

            formToggleIcon.textContent = isOpen ? "−" : "+";

            formToggle.setAttribute("aria-expanded", String(isOpen));
            formContent.inert = !isOpen;
        });

        console.log("Form toggle initialized!");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initializeFormToggle);
    } else {
        initializeFormToggle();
    }

  } catch (error) {

    input.classList.remove(
      "success"
    );


    /*
     * Removing + re-adding the class forces
     * the shake animation to restart.
     */
    input.classList.remove(
      "error"
    );

    void input.offsetWidth;

    input.classList.add(
      "error"
    );


    console.error(
      "Unable to decrypt content:",
      error
    );
  }
}


document.addEventListener(
  "DOMContentLoaded",
  () => {

    const input =
      document.getElementById(
        "password-input"
      );


    input.addEventListener(
      "keydown",
      async event => {

        if (
          event.key !== "Enter"
        ) {
          return;
        }


        await revealContent(
          input.value
        );
      }
    );


    input.focus();
  }
);

