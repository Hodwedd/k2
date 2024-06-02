package control;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import model.DriverManagerConnectionPool;
import model.OrderModel;
import model.UserBean;

/**
 * Servlet implementation class Login
 */
@WebServlet("/Login")
public class Login extends HttpServlet {
    private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public Login() {
        super();
        // TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // TODO Auto-generated method stub
        doPost(request, response);
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // TODO Auto-generated method stub
        String email = request.getParameter("j_email");
        String password = request.getParameter("j_password");
        String redirectedPage = "/loginPage.jsp";
        Boolean control = false;
        try {
            Connection con = DriverManagerConnectionPool.getConnection();
            String sql = "SELECT email, passwordUser, ruolo, nome, cognome, indirizzo, telefono, numero, intestatario, CVV FROM UserAccount WHERE email=?";
            
            PreparedStatement ps = con.prepareStatement(sql);
            ps.setString(1, email);
            ResultSet rs = ps.executeQuery();
            
            if (rs.next()) {
                String storedPassword = rs.getString("passwordUser");
                String hashedPassword = hashPassword(password);
                
                if (hashedPassword.equals(storedPassword)) {
                    control = true;
                    UserBean registeredUser = new UserBean();
                    registeredUser.setEmail(rs.getString("email"));
                    registeredUser.setNome(rs.getString("nome"));
                    registeredUser.setCognome(rs.getString("cognome"));
                    registeredUser.setIndirizzo(rs.getString("indirizzo"));
                    registeredUser.setTelefono(rs.getString("telefono"));
                    registeredUser.setNumero(rs.getString("numero"));
                    registeredUser.setIntestatario(rs.getString("intestatario"));
                    registeredUser.setCvv(rs.getString("CVV"));
                    registeredUser.setRole(rs.getString("ruolo"));
                    request.getSession().setAttribute("registeredUser", registeredUser);
                    request.getSession().setAttribute("role", registeredUser.getRole());
                    request.getSession().setAttribute("email", rs.getString("email"));
                    request.getSession().setAttribute("nome", rs.getString("nome"));
                    
                    OrderModel model = new OrderModel();
                    request.getSession().setAttribute("listaOrdini", model.getOrders(rs.getString("email")));
                    
                    redirectedPage = "/index.jsp";
                }
            }
            con.close();
        }
        catch (SQLException e) {
            e.printStackTrace();
        }
        if (!control) {
            request.getSession().setAttribute("login-error", true);
        }
        else {
            request.getSession().setAttribute("login-error", false);
        }
        response.sendRedirect(request.getContextPath() + redirectedPage);
    }
    
    private String hashPassword(String password) {
        String hashedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes());
            BigInteger number = new BigInteger(1, hashBytes);
            hashedPassword = number.toString(16);
            
            // Pad to make sure the hashed password is of consistent length
            while (hashedPassword.length() < 64) {
                hashedPassword = "0" + hashedPassword;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hashedPassword;
    }

}
