document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('loginForm');
  const otpModal = document.getElementById('otpModal');
  const otpForm = document.getElementById('otpForm');
  const otpMessage = document.getElementById('otpMessage');
  const loader = document.getElementById('loader'); // ✅ Define loader here

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(loginForm);

    loader.style.display = 'flex';

    try{
    const response = await fetch(loginUrl, {
      method: 'POST',
      headers: {
        'X-CSRFToken': formData.get('csrfmiddlewaretoken')
      },
      body: formData
    });

    const data = await response.json();

    if (data.status === 'otp_sent') {
      console.log("OTP modal triggered");
      otpModal.style.display = 'flex';
    } else {
      alert(data.message || 'Login failed');
    }
  } catch (error){
    alert('An error occurred. Please try again.');
  }finally {
      loader.style.display = 'none'; 
    }
  });


  otpForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const otpData = new FormData(otpForm);
    loader.style.display = 'flex';

    try{
    const response = await fetch(verifyOtpUrl, {
      method: 'POST',
      headers: {
        'X-CSRFToken': otpData.get('csrfmiddlewaretoken')
      },
      body: otpData
    });

    const data = await response.json();

    if (data.status === 'verified') {
      window.location.href = data.redirect_url || '/';
    } else {
      otpMessage.textContent = data.message || 'Invalid OTP';
    }
  }catch (error) {
      otpMessage.textContent = 'Something went wrong.';
    } finally {
      loader.style.display = 'none';
    }
  });
});