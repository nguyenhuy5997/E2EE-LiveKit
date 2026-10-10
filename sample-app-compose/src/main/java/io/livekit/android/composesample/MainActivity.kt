/*
 * Copyright 2023-2026 LiveKit, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.livekit.android.composesample

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.RadioButton
import androidx.compose.material.Surface
import androidx.compose.material.Switch
import androidx.compose.material.Tab
import androidx.compose.material.TabRow
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import io.livekit.android.composesample.ui.theme.AppTheme
import io.livekit.android.sample.MainViewModel
import io.livekit.android.sample.common.R
import io.livekit.android.sample.model.StressTest
import io.livekit.android.sample.model.TokenSourceArgs
import io.livekit.android.sample.util.requestNeededPermissions

private enum class TokenMode {
    Literal,
    DevServer,
}

class MainActivity : ComponentActivity() {

    private val viewModel by viewModels<MainViewModel>()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        requestNeededPermissions()
        setContent {
            MainContent(
                defaultUrl = viewModel.getSavedUrl(),
                defaultToken = viewModel.getSavedToken(),
                defaultTokenServerId = viewModel.getSavedTokenServerId(),
                defaultE2eeKey = viewModel.getSavedE2EEKey(),
                defaultE2eeOn = viewModel.getE2EEOptionsOn(),
                defaultE2eeOnBoard = viewModel.getE2EEOnBoard(),
                onConnect = { tokenSourceArgs, e2eeKey, e2eeOn, e2eeOnBoard, stressTest ->
                    val intent = Intent(this@MainActivity, CallActivity::class.java).apply {
                        putExtra(
                            CallActivity.KEY_ARGS,
                            CallActivity.BundleArgs(
                                tokenSourceArgs,
                                e2eeKey,
                                e2eeOn,
                                stressTest,
                                e2eeOnBoard,
                            ),
                        )
                    }
                    startActivity(intent)
                },
                onSave = { url, token, tokenServerId, e2eeKey, e2eeOn, e2eeOnBoard ->
                    viewModel.setSavedUrl(url)
                    viewModel.setSavedToken(token)
                    viewModel.setSavedTokenServerId(tokenServerId)
                    viewModel.setSavedE2EEKey(e2eeKey)
                    viewModel.setSavedE2EEOn(e2eeOn)
                    viewModel.setE2EEOnBoard(e2eeOnBoard)

                    Toast.makeText(
                        this@MainActivity,
                        "Values saved.",
                        Toast.LENGTH_SHORT,
                    ).show()
                },
                onReset = {
                    viewModel.reset()
                    Toast.makeText(
                        this@MainActivity,
                        "Values reset.",
                        Toast.LENGTH_SHORT,
                    ).show()
                },
            )
        }
    }

    @Preview(
        showBackground = true,
        showSystemUi = true,
    )
    @Composable
    fun MainContent(
        defaultUrl: String = MainViewModel.URL,
        defaultToken: String = MainViewModel.TOKEN,
        defaultSecondToken: String = MainViewModel.TOKEN,
        defaultTokenServerId: String = MainViewModel.TOKEN_SERVER_ID,
        defaultE2eeKey: String = MainViewModel.E2EE_KEY,
        defaultE2eeOn: Boolean = false,
        defaultE2eeOnBoard: Boolean = true,
        onConnect: (tokenSourceArgs: TokenSourceArgs, e2eeKey: String, e2eeOn: Boolean, e2eeOnBoard: Boolean, stressTest: StressTest) -> Unit = { _, _, _, _, _ -> },
        onSave: (url: String, token: String, tokenServerId: String, e2eeKey: String, e2eeOn: Boolean, e2eeOnBoard: Boolean) -> Unit = { _, _, _, _, _, _ -> },
        onReset: () -> Unit = {},
    ) {
        AppTheme {
            var tokenMode by remember { mutableStateOf(TokenMode.Literal) }
            var url by remember { mutableStateOf(defaultUrl) }
            var token by remember { mutableStateOf(defaultToken) }
            var tokenServerId by remember { mutableStateOf(defaultTokenServerId) }
            var roomName by remember { mutableStateOf("") }
            var participantName by remember { mutableStateOf("") }
            var participantIdentity by remember { mutableStateOf("") }
            var agentName by remember { mutableStateOf("") }
            var e2eeKey by remember { mutableStateOf(defaultE2eeKey) }
            var e2eeOn by remember { mutableStateOf(defaultE2eeOn) }
            var e2eeOnBoard by remember { mutableStateOf(defaultE2eeOnBoard) }
            var stressTest by remember { mutableStateOf(false) }
            var secondToken by remember { mutableStateOf(defaultSecondToken) }
            val scrollState = rememberScrollState()
            // A surface container using the 'background' color from the theme
            Surface(
                color = MaterialTheme.colors.background,
                modifier = Modifier
                    .fillMaxSize(),
            ) {
                Box(
                    modifier = Modifier
                        .verticalScroll(scrollState),
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier
                            .padding(10.dp),
                    ) {
                        Spacer(modifier = Modifier.height(50.dp))
                        Image(
                            painter = painterResource(id = R.drawable.banner_dark),
                            contentDescription = "",
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        TabRow(
                            selectedTabIndex = tokenMode.ordinal,
                            backgroundColor = Color.Transparent,
                        ) {
                            Tab(
                                selected = tokenMode == TokenMode.Literal,
                                onClick = { tokenMode = TokenMode.Literal },
                                text = { Text("URL & Token") },
                            )
                            Tab(
                                selected = tokenMode == TokenMode.DevServer,
                                onClick = { tokenMode = TokenMode.DevServer },
                                text = { Text("Dev Token Server") },
                            )
                        }
                        when (tokenMode) {
                            TokenMode.Literal -> {
                                Spacer(modifier = Modifier.height(20.dp))
                                OutlinedTextField(
                                    value = url,
                                    onValueChange = { url = it },
                                    label = { Text("URL") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(modifier = Modifier.height(20.dp))
                                OutlinedTextField(
                                    value = token,
                                    onValueChange = { token = it },
                                    label = { Text("Token") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }

                            TokenMode.DevServer -> {
                                Spacer(modifier = Modifier.height(20.dp))
                                OutlinedTextField(
                                    value = tokenServerId,
                                    onValueChange = { tokenServerId = it },
                                    label = { Text("Token Server ID") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(modifier = Modifier.height(20.dp))
                                OutlinedTextField(
                                    value = roomName,
                                    onValueChange = { roomName = it },
                                    label = { Text("Room Name (optional)") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(modifier = Modifier.height(20.dp))
                                OutlinedTextField(
                                    value = participantName,
                                    onValueChange = { participantName = it },
                                    label = { Text("Participant Name (optional)") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(modifier = Modifier.height(20.dp))
                                OutlinedTextField(
                                    value = participantIdentity,
                                    onValueChange = { participantIdentity = it },
                                    label = { Text("Participant Identity (optional)") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(modifier = Modifier.height(20.dp))
                                OutlinedTextField(
                                    value = agentName,
                                    onValueChange = { agentName = it },
                                    label = { Text("Agent Name (optional)") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                        }

                        if (tokenMode == TokenMode.Literal && stressTest) {
                            Spacer(modifier = Modifier.height(20.dp))
                            OutlinedTextField(
                                value = secondToken,
                                onValueChange = { secondToken = it },
                                label = { Text("Second token") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = stressTest,
                            )
                        }

                        Spacer(modifier = Modifier.height(20.dp))
                        Row(
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Bật E2EE (mã hóa đầu cuối)")
                            Switch(
                                checked = e2eeOn,
                                onCheckedChange = { e2eeOn = it },
                            )
                        }

                        // EVT2: where the end-to-end encryption runs. Both phones must choose the same mode.
                        if (e2eeOn) {
                            E2eeModeOption(
                                text = "Mã hóa qua QRNG-SDCARD",
                                selected = e2eeOnBoard,
                                onSelect = { e2eeOnBoard = true },
                            )
                            E2eeModeOption(
                                text = "Mã hóa qua App",
                                selected = !e2eeOnBoard,
                                onSelect = { e2eeOnBoard = false },
                            )
                            if (!e2eeOnBoard) {
                                Spacer(modifier = Modifier.height(10.dp))
                                OutlinedTextField(
                                    value = e2eeKey,
                                    onValueChange = { e2eeKey = it },
                                    label = { Text("Khóa E2EE (giống nhau trên hai máy)") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                        }

                        if (tokenMode == TokenMode.Literal) {
                            Row(
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text("Stress test")
                                Switch(
                                    checked = stressTest,
                                    onCheckedChange = { stressTest = it },
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(40.dp))
                        Button(
                            onClick = {
                                when (tokenMode) {
                                    TokenMode.Literal -> {
                                        val stressTestCmd = if (stressTest) {
                                            StressTest.SwitchRoom(token, secondToken)
                                        } else {
                                            StressTest.None
                                        }
                                        onConnect(TokenSourceArgs.Literal(url, token), e2eeKey, e2eeOn, e2eeOnBoard, stressTestCmd)
                                    }

                                    TokenMode.DevServer -> {
                                        val devTokenServerArgs = TokenSourceArgs.DevTokenServer(
                                            tokenServerId = tokenServerId,
                                            roomName = roomName.ifBlank { null },
                                            participantName = participantName.ifBlank { null },
                                            participantIdentity = participantIdentity.ifBlank { null },
                                            agentName = agentName.ifBlank { null },
                                        )
                                        onConnect(devTokenServerArgs, e2eeKey, e2eeOn, e2eeOnBoard, StressTest.None)
                                    }
                                }
                            },
                        ) {
                            Text("Connect")
                        }

                        Spacer(modifier = Modifier.height(20.dp))
                        Button(onClick = { onSave(url, token, tokenServerId, e2eeKey, e2eeOn, e2eeOnBoard) }) {
                            Text("Save Values")
                        }

                        Spacer(modifier = Modifier.height(20.dp))
                        Button(
                            onClick = {
                                onReset()
                                url = MainViewModel.URL
                                token = MainViewModel.TOKEN
                                tokenServerId = MainViewModel.TOKEN_SERVER_ID
                            },
                        ) {
                            Text("Reset Values")
                        }
                    }
                }
            }
        }
    }
}

/** One choice of where E2EE runs (a radio button row). */
@Composable
private fun E2eeModeOption(text: String, selected: Boolean, onSelect: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onSelect, role = Role.RadioButton)
            .padding(vertical = 4.dp),
    ) {
        RadioButton(selected = selected, onClick = null)
        Spacer(modifier = Modifier.width(8.dp))
        Text(text)
    }
}

