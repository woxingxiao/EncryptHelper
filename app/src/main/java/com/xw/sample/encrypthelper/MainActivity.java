package com.xw.sample.encrypthelper;

import android.content.Context;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.xw.repo.security.EncryptHelper;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    EditText mInputEdit;
    Button mEncryptBtn;
    Button mDecryptBtn;
    TextView mEncryptTv;
    TextView mDecryptTv;

    private EncryptHelper mEncryptHelper;
    private String mEncryptedText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mInputEdit = (EditText) findViewById(R.id.input_edit);
        mEncryptBtn = (Button) findViewById(R.id.encrypt_button);
        mDecryptBtn = (Button) findViewById(R.id.decrypt_button);
        mEncryptTv = (TextView) findViewById(R.id.encrypted_text);
        mDecryptTv = (TextView) findViewById(R.id.decrypted_text);

        mEncryptBtn.setOnClickListener(this);
        mDecryptBtn.setOnClickListener(this);

        mEncryptHelper = new EncryptHelper(getApplicationContext());
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.encrypt_button:
                String text = mInputEdit.getText().toString();

                if (text.isEmpty()) {
                    Toast.makeText(this, "The text is empty.", Toast.LENGTH_SHORT).show();
                } else {
                    InputMethodManager inputManager = (InputMethodManager) getSystemService(
                            Context.INPUT_METHOD_SERVICE);
                    inputManager.hideSoftInputFromWindow(mInputEdit.getWindowToken(), 0);

                    try {
                        mEncryptedText = mEncryptHelper.encrypt(text);

                        mEncryptTv.setText(mEncryptedText);
                        mDecryptBtn.setEnabled(true);
                    } catch (Exception e) {
                        e.printStackTrace();

                        mEncryptTv.setText("");
                        mDecryptBtn.setEnabled(false);
                    }

                    mDecryptTv.setText("");
                }

                break;
            case R.id.decrypt_button:
                try {
                    String decryptText = mEncryptHelper.decrypt(mEncryptedText);

                    mDecryptTv.setText(decryptText);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                mDecryptBtn.setEnabled(false);

                break;
        }
    }

}
