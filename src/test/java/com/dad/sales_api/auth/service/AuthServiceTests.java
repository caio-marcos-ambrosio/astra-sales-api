package com.dad.sales_api.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.dad.sales_api.auth.dto.input.ChangePasswordInputDTO;
import com.dad.sales_api.auth.dto.input.LoginInputDTO;
import com.dad.sales_api.auth.dto.input.RegisterInputDTO;
import com.dad.sales_api.auth.dto.input.SendCodeInputDTO;
import com.dad.sales_api.auth.dto.input.ValidateCodeInputDTO;
import com.dad.sales_api.auth.dto.output.LoginOutputDTO;
import com.dad.sales_api.auth.dto.output.RegisterOutputDTO;
import com.dad.sales_api.auth.dto.output.SendCodeOutputDTO;
import com.dad.sales_api.auth.dto.output.ValidateCodeOutputDTO;
import com.dad.sales_api.shared.config.CustomUserDetails;
import com.dad.sales_api.shared.config.JwtUtils;
import com.dad.sales_api.shared.enums.RoleEnum;
import com.dad.sales_api.shared.exceptions.BadRequestException;
import com.dad.sales_api.shared.exceptions.UnauthorizedException;
import com.dad.sales_api.shared.helpers.dto.ValidatorOutputDTO;
import com.dad.sales_api.shared.helpers.services.CpfValidatorService;
import com.dad.sales_api.shared.helpers.services.EmailService;
import com.dad.sales_api.shared.helpers.services.MessageService;
import com.dad.sales_api.shared.persistence.mongo.documents.PasswordResetCode;
import com.dad.sales_api.shared.persistence.mongo.repositories.PasswordResetCodeRepository;
import com.dad.sales_api.shared.persistence.postgres.entities.UserEntity;
import com.dad.sales_api.shared.persistence.postgres.repositories.UserRepository;
import java.time.LocalDateTime;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Testes unitários do AuthService. Todas as dependências são mocks: nenhum
 * banco de dados, e-mail ou API externa é acessado.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTests {

  @Mock private UserRepository userRepository;
  @Mock private PasswordResetCodeRepository passwordResetCodeRepository;
  @Mock private UserDetailsService userDetailsService;
  @Mock private EmailService emailService;
  @Mock private CpfValidatorService cpfValidatorService;
  @Mock private MessageService messageService;
  @Mock private PasswordEncoder passwordEncoder;
  @Mock private JwtUtils jwtUtils;
  @Mock private Random random;

  private AuthService authService;

  @BeforeEach
  void setUp() {
    // As mensagens retornam a própria chave, o que permite validar qual
    // mensagem de erro cada fluxo utiliza.
    lenient().when(messageService.getMessage(anyString()))
        .thenAnswer(invocation -> invocation.getArgument(0));

    authService = new AuthService(
        userRepository,
        passwordResetCodeRepository,
        userDetailsService,
        emailService,
        cpfValidatorService,
        messageService,
        passwordEncoder,
        jwtUtils,
        random
    );
  }

  // ---------------------------------------------------------------------------
  // login
  // ---------------------------------------------------------------------------
  @Nested
  @DisplayName("login")
  class Login {

    @Test
    @DisplayName("retorna o token quando as credenciais são válidas")
    void shouldReturnTokenWhenCredentialsAreValid() {
      CustomUserDetails user =
          new CustomUserDetails(7, "maria@email.com", "hash", RoleEnum.CUSTOMER);

      when(userDetailsService.loadUserByUsername("maria@email.com")).thenReturn(user);
      when(passwordEncoder.matches("Senha123", "hash")).thenReturn(true);
      when(jwtUtils.generateToken("maria@email.com", RoleEnum.CUSTOMER, 7)).thenReturn("jwt-token");

      LoginOutputDTO result = authService.login(new LoginInputDTO("maria@email.com", "Senha123"));

      assertThat(result.token()).isEqualTo("jwt-token");
      assertThat(result.message()).isEqualTo("login.realized");
    }

    @Test
    @DisplayName("lança UnauthorizedException e não gera token quando a senha está incorreta")
    void shouldThrowUnauthorizedWhenPasswordIsWrong() {
      CustomUserDetails user =
          new CustomUserDetails(7, "maria@email.com", "hash", RoleEnum.CUSTOMER);

      when(userDetailsService.loadUserByUsername("maria@email.com")).thenReturn(user);
      when(passwordEncoder.matches("errada", "hash")).thenReturn(false);

      assertThatThrownBy(() -> authService.login(new LoginInputDTO("maria@email.com", "errada")))
          .isInstanceOf(UnauthorizedException.class)
          .hasMessage("exception.login.unhautorized");

      verifyNoInteractions(jwtUtils);
    }

    @Test
    @DisplayName("propaga UsernameNotFoundException quando o usuário não existe")
    void shouldPropagateWhenUserDoesNotExist() {
      when(userDetailsService.loadUserByUsername("ninguem@email.com"))
          .thenThrow(new UsernameNotFoundException("not found"));

      assertThatThrownBy(() -> authService.login(new LoginInputDTO("ninguem@email.com", "Senha123")))
          .isInstanceOf(UsernameNotFoundException.class);

      verifyNoInteractions(passwordEncoder, jwtUtils);
    }
  }

  // ---------------------------------------------------------------------------
  // register
  // ---------------------------------------------------------------------------
  @Nested
  @DisplayName("register")
  class Register {

    private final RegisterInputDTO input =
        new RegisterInputDTO("Maria Souza", "maria@email.com", "Senha123", "12345678910");

    @Test
    @DisplayName("cria o usuário como CUSTOMER com a senha criptografada")
    void shouldCreateCustomerWithEncodedPassword() {
      when(cpfValidatorService.validateCpf("12345678910"))
          .thenReturn(new ValidatorOutputDTO(true, "cpf", "123.456.789-10"));
      when(userRepository.findByEmail("maria@email.com")).thenReturn(null);
      when(userRepository.findByCpf("12345678910")).thenReturn(null);
      when(passwordEncoder.encode("Senha123")).thenReturn("hash-da-senha");

      RegisterOutputDTO result = authService.register(input);

      ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);
      verify(userRepository).save(captor.capture());

      UserEntity saved = captor.getValue();
      assertThat(saved.getName()).isEqualTo("Maria Souza");
      assertThat(saved.getEmail()).isEqualTo("maria@email.com");
      assertThat(saved.getCpf()).isEqualTo("12345678910");
      assertThat(saved.getRole()).isEqualTo(RoleEnum.CUSTOMER);
      assertThat(saved.getPassword()).isEqualTo("hash-da-senha");

      assertThat(result.email()).isEqualTo("maria@email.com");
      assertThat(result.cpf()).isEqualTo("123.456.789-10");
    }

    @Test
    @DisplayName("lança BadRequestException quando o CPF é inválido")
    void shouldThrowWhenCpfIsInvalid() {
      when(cpfValidatorService.validateCpf("12345678910"))
          .thenReturn(new ValidatorOutputDTO(false, "cpf", null));

      assertThatThrownBy(() -> authService.register(input))
          .isInstanceOf(BadRequestException.class)
          .hasMessage("validation.cpf.exists");

      verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("lança BadRequestException quando o e-mail já está cadastrado")
    void shouldThrowWhenEmailAlreadyExists() {
      when(cpfValidatorService.validateCpf("12345678910"))
          .thenReturn(new ValidatorOutputDTO(true, "cpf", "123.456.789-10"));
      when(userRepository.findByEmail("maria@email.com")).thenReturn(new UserEntity());

      assertThatThrownBy(() -> authService.register(input))
          .isInstanceOf(BadRequestException.class)
          .hasMessage("validation.email.invalid");

      verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("lança BadRequestException quando o CPF já está cadastrado")
    void shouldThrowWhenCpfAlreadyExists() {
      when(cpfValidatorService.validateCpf("12345678910"))
          .thenReturn(new ValidatorOutputDTO(true, "cpf", "123.456.789-10"));
      when(userRepository.findByEmail("maria@email.com")).thenReturn(null);
      when(userRepository.findByCpf("12345678910")).thenReturn(new UserEntity());

      assertThatThrownBy(() -> authService.register(input))
          .isInstanceOf(BadRequestException.class)
          .hasMessage("validation.cpf.invalid");

      verify(userRepository, never()).save(any());
    }
  }

  // ---------------------------------------------------------------------------
  // sendCode
  // ---------------------------------------------------------------------------
  @Nested
  @DisplayName("sendCode")
  class SendCode {

    @Test
    @DisplayName("gera o código, salva com validade de 15 minutos e envia o e-mail")
    void shouldGenerateSaveAndSendCode() throws Exception {
      UserEntity user = new UserEntity();
      user.setRole(RoleEnum.CUSTOMER);

      when(userRepository.findByEmail("maria@email.com")).thenReturn(user);
      when(passwordResetCodeRepository.findByEmail("maria@email.com")).thenReturn(null);
      when(random.nextInt(900000)).thenReturn(123456);

      LocalDateTime before = LocalDateTime.now();
      SendCodeOutputDTO result = authService.sendCode(new SendCodeInputDTO("maria@email.com"));

      ArgumentCaptor<PasswordResetCode> captor = ArgumentCaptor.forClass(PasswordResetCode.class);
      verify(passwordResetCodeRepository).save(captor.capture());

      PasswordResetCode saved = captor.getValue();
      assertThat(saved.getEmail()).isEqualTo("maria@email.com");
      assertThat(saved.getRole()).isEqualTo(RoleEnum.CUSTOMER);
      assertThat(saved.getCode()).isEqualTo("223456"); // 100000 + 123456
      assertThat(saved.getUsed()).isFalse();
      assertThat(saved.getExpiresAt())
          .isAfter(before.plusMinutes(14))
          .isBefore(LocalDateTime.now().plusMinutes(16));

      verify(emailService).send(
          eq("maria@email.com"),
          eq("Recuperação de senha"),
          contains("223456")
      );
      assertThat(result.email()).isEqualTo("maria@email.com");
    }

    @Test
    @DisplayName("não gera código nem envia e-mail quando o usuário não existe, mas responde igual")
    void shouldDoNothingWhenUserDoesNotExist() throws Exception {
      when(userRepository.findByEmail("ninguem@email.com")).thenReturn(null);

      SendCodeOutputDTO result = authService.sendCode(new SendCodeInputDTO("ninguem@email.com"));

      verifyNoInteractions(passwordResetCodeRepository, emailService);
      assertThat(result.email()).isEqualTo("ninguem@email.com");
    }

    @Test
    @DisplayName("não gera um novo código quando já existe um para o e-mail")
    void shouldNotGenerateNewCodeWhenOneAlreadyExists() throws Exception {
      UserEntity user = new UserEntity();
      user.setRole(RoleEnum.CUSTOMER);

      when(userRepository.findByEmail("maria@email.com")).thenReturn(user);
      when(passwordResetCodeRepository.findByEmail("maria@email.com"))
          .thenReturn(new PasswordResetCode());

      authService.sendCode(new SendCodeInputDTO("maria@email.com"));

      verify(passwordResetCodeRepository, never()).save(any());
      verifyNoInteractions(emailService);
    }
  }

  // ---------------------------------------------------------------------------
  // validateCode
  // ---------------------------------------------------------------------------
  @Nested
  @DisplayName("validateCode")
  class ValidateCode {

    private PasswordResetCode storedCode() {
      return new PasswordResetCode(
          "maria@email.com", RoleEnum.CUSTOMER, "123456", LocalDateTime.now().plusMinutes(10));
    }

    @Test
    @DisplayName("marca o código como usado quando ele está correto")
    void shouldMarkCodeAsUsedWhenCorrect() {
      PasswordResetCode stored = storedCode();
      when(passwordResetCodeRepository.findByEmailAndUsed("maria@email.com", Boolean.FALSE))
          .thenReturn(stored);

      ValidateCodeOutputDTO result =
          authService.validateCode(new ValidateCodeInputDTO("maria@email.com", "123456"));

      assertThat(result.valid()).isTrue();
      assertThat(result.code()).isEqualTo("123456");
      assertThat(stored.getUsed()).isTrue();
      verify(passwordResetCodeRepository).save(stored);
    }

    @Test
    @DisplayName("lança UnauthorizedException quando o código está incorreto")
    void shouldThrowWhenCodeIsWrong() {
      PasswordResetCode stored = storedCode();
      when(passwordResetCodeRepository.findByEmailAndUsed("maria@email.com", Boolean.FALSE))
          .thenReturn(stored);

      assertThatThrownBy(() ->
          authService.validateCode(new ValidateCodeInputDTO("maria@email.com", "000000")))
          .isInstanceOf(UnauthorizedException.class)
          .hasMessage("validation.change-password.code.incorrect");

      assertThat(stored.getUsed()).isFalse();
      verify(passwordResetCodeRepository, never()).save(any());
    }

    @Test
    @DisplayName("lança UnauthorizedException quando não há código pendente para o e-mail")
    void shouldThrowWhenThereIsNoPendingCode() {
      when(passwordResetCodeRepository.findByEmailAndUsed("maria@email.com", Boolean.FALSE))
          .thenReturn(null);

      assertThatThrownBy(() ->
          authService.validateCode(new ValidateCodeInputDTO("maria@email.com", "123456")))
          .isInstanceOf(UnauthorizedException.class)
          .hasMessage("validation.change-password.code.incorrect");
    }
  }

  // ---------------------------------------------------------------------------
  // changePassword
  // ---------------------------------------------------------------------------
  @Nested
  @DisplayName("changePassword")
  class ChangePassword {

    private PasswordResetCode usedCode() {
      PasswordResetCode code = new PasswordResetCode(
          "maria@email.com", RoleEnum.CUSTOMER, "123456", LocalDateTime.now().plusMinutes(10));
      code.setUsed(true);
      return code;
    }

    @Test
    @DisplayName("atualiza a senha criptografada quando o código foi validado e as senhas coincidem")
    void shouldUpdatePasswordWhenCodeAndPasswordsAreValid() {
      UserEntity user = new UserEntity();
      user.setPassword("hash-antigo");

      when(passwordResetCodeRepository.findByEmailAndUsed("maria@email.com", Boolean.TRUE))
          .thenReturn(usedCode());
      when(userRepository.findByEmail("maria@email.com")).thenReturn(user);
      when(passwordEncoder.encode("NovaSenha1")).thenReturn("hash-novo");

      authService.changePassword(
          new ChangePasswordInputDTO("maria@email.com", "123456", "NovaSenha1", "NovaSenha1"));

      assertThat(user.getPassword()).isEqualTo("hash-novo");
      verify(userRepository).save(user);
    }

    @Test
    @DisplayName("lança UnauthorizedException quando o código informado não confere")
    void shouldThrowWhenCodeDoesNotMatch() {
      when(passwordResetCodeRepository.findByEmailAndUsed("maria@email.com", Boolean.TRUE))
          .thenReturn(usedCode());

      assertThatThrownBy(() -> authService.changePassword(
          new ChangePasswordInputDTO("maria@email.com", "000000", "NovaSenha1", "NovaSenha1")))
          .isInstanceOf(UnauthorizedException.class)
          .hasMessage("validation.change-password.code.incorrect");

      verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("lança BadRequestException quando a confirmação de senha é diferente")
    void shouldThrowWhenPasswordsDoNotMatch() {
      when(passwordResetCodeRepository.findByEmailAndUsed("maria@email.com", Boolean.TRUE))
          .thenReturn(usedCode());

      assertThatThrownBy(() -> authService.changePassword(
          new ChangePasswordInputDTO("maria@email.com", "123456", "NovaSenha1", "Outra1234")))
          .isInstanceOf(BadRequestException.class)
          .hasMessage("validation.change-password.incorrect");

      verify(userRepository, never()).save(any());
      verifyNoInteractions(passwordEncoder);
    }
  }
}